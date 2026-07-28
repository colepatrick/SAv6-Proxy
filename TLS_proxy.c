#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define CLOSESOCK closesocket
typedef HANDLE thread_t;
typedef CRITICAL_SECTION mutex_t;
#define THREAD_RET DWORD
#define THREAD_CALL WINAPI
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

typedef int socket_t;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSESOCK close
typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
#define THREAD_RET void *
#define THREAD_CALL
#endif

#include <math.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#define BUF_SIZE 65536

/*
 * One route is one master<->outstation pairing served by this process: a local
 * listen port paired with a remote connect target. A single master-side process
 * with N routes talks to N distinct outstation-side proxies (point-to-multipoint);
 * an outstation-side process normally has exactly one route (it fronts one device),
 * but the same mechanism lets one outstation-side process front several devices too.
 */
struct route {
    int id;
    const char *listen_host;
    const char *listen_port;
    const char *connect_host;
    const char *connect_port;
};

#define ADMIN_CMD_NONE 0
#define ADMIN_CMD_ADD 1
#define ADMIN_CMD_REMOVE 2
#define ADMIN_CMD_LIST 3

struct config {
    int is_master;

    const char *listen_host;
    struct route *routes;
    int route_count;

    const char *cert_path;
    const char *key_path;
    const char *ca_path;

    int insecure;    /* if non-zero, skip peer/host verification */
    int verify_peer; /* if non-zero, verify peer cert (uses ca_path if provided) */

    int auto_cert; /* if non-zero, generate ephemeral server cert/key when --cert/--key missing (outstation mode) */

    int timeout_ms; /* for handshake and I/O select timeouts */

    int verbose;   /* print detailed connection/TLS information */
    int log_keys;  /* dump sensitive key/symmetric material (debug only) */

    int use_ml_kem_512; /* if non-zero, use ML-KEM-512 (post-quantum) for key exchange */

    /* Admin control channel (server side): set control_port to enable it. */
    const char *control_host;
    const char *control_port;

    /* Admin client mode: this invocation manages a running instance instead
     * of starting a proxy itself. Set when --admin is given. */
    int admin_mode;
    const char *admin_host;
    const char *admin_port;
    int admin_cmd;
    char *admin_add_spec;
    int admin_remove_id;

    /* Self-registration (outstation mode only): if announce_admin_host/port
     * are set (from --announce-to), every route this process serves calls
     * the given master's admin channel with an ADD command right after its
     * listener binds -- the same thing --admin ...--add does by hand, just
     * automatic. announce_host (--announce-host) is what to advertise this
     * proxy as; NULL means auto-detect the outbound local IP. */
    const char *announce_host;
    const char *announce_admin_host;
    const char *announce_admin_port;
};

struct channel {
    socket_t plain_sock;
    socket_t tcp_secure_sock;

    SSL_CTX *ssl_ctx;
    SSL *ssl;

    int is_master;
    int route_id;
    /* Packet statistics tracking */
    uint64_t *plaintext_sizes;  /* Array of plaintext packet sizes */
    uint64_t *encrypted_sizes;  /* Array of encrypted packet sizes */
    uint64_t plaintext_count;   /* Number of plaintext packets received */
    uint64_t encrypted_count;   /* Number of encrypted packets received */
    uint64_t plaintext_capacity;/* Allocated array size for plaintext */
    uint64_t encrypted_capacity;/* Allocated array size for encrypted */
};

/*
 * Minimal cross-platform thread/mutex wrappers. Each route (one master<->outstation
 * pairing) runs its own persistent thread with its own struct channel, so the only
 * shared mutable state across threads is stdout, which log_lock/log_unlock protect.
 */
static mutex_t g_log_mutex;

static void mutex_init(mutex_t *m)
{
#ifdef _WIN32
    InitializeCriticalSection(m);
#else
    pthread_mutex_init(m, NULL);
#endif
}

static void mtx_lock(mutex_t *m)
{
#ifdef _WIN32
    EnterCriticalSection(m);
#else
    pthread_mutex_lock(m);
#endif
}

static void mtx_unlock(mutex_t *m)
{
#ifdef _WIN32
    LeaveCriticalSection(m);
#else
    pthread_mutex_unlock(m);
#endif
}

static void log_lock(void) { mtx_lock(&g_log_mutex); }
static void log_unlock(void) { mtx_unlock(&g_log_mutex); }

static int thread_create(thread_t *t, THREAD_RET (THREAD_CALL *fn)(void *), void *arg)
{
#ifdef _WIN32
    *t = CreateThread(NULL, 0, fn, arg, 0, NULL);
    return *t ? 0 : -1;
#else
    return pthread_create(t, NULL, fn, arg) == 0 ? 0 : -1;
#endif
}

static void thread_join(thread_t t)
{
#ifdef _WIN32
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
#else
    pthread_join(t, NULL);
#endif
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage (single point-to-point route):\n"
        "  %s --mode master   [--listen-host HOST] --listen-port PLAIN_PORT --connect-host PROXY_HOST --connect-port PROXY_PORT [--ca PATH] [--cert PATH --key PATH] [--insecure] [--timeout-ms MS] [--verbose] [--log-keys] [--ml-kem]\n"
        "  %s --mode outstation [--listen-host HOST] --listen-port PROXY_PORT --connect-host SAv5_HOST --connect-port SAv5_PORT --cert PATH --key PATH [--ca PATH] [--insecure] [--timeout-ms MS] [--verbose] [--log-keys] [--ml-kem]\n\n"
        "Usage (point-to-multipoint, one process serving several outstations):\n"
        "  %s --mode master   [--listen-host HOST] --route PLAIN_PORT:PROXY_HOST:PROXY_PORT [--route ...] [other options]\n"
        "  %s --mode outstation [--listen-host HOST] --route PROXY_PORT:SAv5_HOST:SAv5_PORT [--route ...] --cert PATH --key PATH [other options]\n\n"
        "This proxy replaces the SAV6 custom secure channel with standard TLS.\n"
        "Stations on each side see only raw plaintext bytes relayed through TLS.\n\n"
        "Common options:\n"
        "  --listen-host HOST   bind address (default: * / all interfaces)\n"
        "  --listen-port PORT   local listening port (plaintext input for master, TLS server input for outstation)\n"
        "  --connect-host HOST connect target host\n"
        "  --connect-port PORT connect target port\n"
        "  --route PORT:HOST:PORT   repeatable full listen+connect pairing; one thread and TLS session per\n"
        "                       route, so one process can serve several outstations (or front several local\n"
        "                       devices). Cannot be mixed with --listen-port/--connect-host/--connect-port.\n"
        "  --insecure           do not verify peer certificate (default for convenience)\n"
        "  --ca PATH            CA bundle to use when verifying (only if verification enabled)\n"
        "  --timeout-ms MS      optional timeout used for TLS handshake and relay loop; default 0 (blocking)\n"
        "  --verbose            print detailed TLS/cert/session information and per-read/write sizes\n"
        "  --log-keys           ALSO dump sensitive key/symmetric material (includes TLS randoms; not safe for production)\n"
        "  --ml-kem         use ML-KEM-512 (post-quantum) key encapsulation mechanism for key exchange\n"
        "                       Requires OpenSSL 3.2+ with ML-KEM support\n"
        "All routes in one process share the same cert/key/CA/TLS options; a route's listener keeps\n"
        "serving new connections after a session ends.\n\n"
        "Optional admin control channel (add/remove routes at runtime, no restart):\n"
        "  %s --mode ... --control-port PORT [--control-host HOST] ...   (server; HOST defaults to 127.0.0.1)\n"
        "  %s --admin CONTROL_HOST:CONTROL_PORT --add LISTEN_PORT:CONNECT_HOST:CONNECT_PORT\n"
        "  %s --admin CONTROL_HOST:CONTROL_PORT --remove ROUTE_ID\n"
        "  %s --admin CONTROL_HOST:CONTROL_PORT --list\n"
        "A new route added this way inherits the running process's mode/cert/TLS settings; only its\n"
        "listen/connect endpoints are specified. REMOVE stops that route's listener and any in-progress\n"
        "session (within about a second) without touching other routes.\n\n"
        "Optional self-registration (outstation mode only, so a new outstation doesn't have to be\n"
        "added to its master by hand):\n"
        "  %s --mode outstation ... --announce-to MASTER_ADMIN_HOST:PORT [--announce-host HOST] ...\n"
        "As soon as each of this process's routes finishes binding its listener, it sends the given\n"
        "master's admin channel the exact same ADD command --admin/--add would (retried a few times,\n"
        "2s apart, in case the master isn't up yet) -- the master-side port requested is this route's\n"
        "own listen port, and the advertised connect host defaults to this host's detected outbound\n"
        "IP unless --announce-host overrides it. This applies to every route the process ever serves,\n"
        "including ones added later via the admin channel, not just the ones given at startup.\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

static int socket_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    return 0;
#endif
}

static void socket_done(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

static socket_t connect_tcp(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL, *rp;
    socket_t s = INVALID_SOCKET;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(host, port, &hints, &res) != 0) return INVALID_SOCKET;
    for (rp = res; rp; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (connect(s, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
        CLOSESOCK(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
}

static socket_t listen_tcp(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL, *rp;
    socket_t s = INVALID_SOCKET;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (!host) hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(host, port, &hints, &res) != 0) return INVALID_SOCKET;
    for (rp = res; rp; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
        if (bind(s, rp->ai_addr, (int)rp->ai_addrlen) == 0 && listen(s, 8) == 0) break;
        CLOSESOCK(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
}

/* Ensures a complete buffer is written; send() may deliver fewer bytes than requested per call. */
static int send_all(socket_t s, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    while (len > 0) {
        int n = send(s, (const char *)p, (int)len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static long parse_long(const char *s, long *out)
{
    char *end = NULL;
    long v;
    if (!s || !s[0]) return -1;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || !end || *end) return -1;
    *out = v;
    return 0;
}

/*
 * Append a route parsed from a "LISTEN_PORT:CONNECT_HOST:CONNECT_PORT" string
 * to cfg->routes, growing the array as needed.
 */
static int add_route_from_spec(struct config *cfg, char *spec)
{
    char *first_colon, *last_colon;
    struct route *tmp;
    struct route r;

    first_colon = strchr(spec, ':');
    last_colon = strrchr(spec, ':');
    if (!first_colon || first_colon == last_colon) return -1;
    *first_colon = '\0';
    *last_colon = '\0';
    r.id = cfg->route_count;
    r.listen_host = NULL; /* backfilled from cfg->listen_host once parsing completes */
    r.listen_port = spec;
    r.connect_host = first_colon + 1;
    r.connect_port = last_colon + 1;
    if (!r.listen_port[0] || !r.connect_host[0] || !r.connect_port[0]) return -1;

    tmp = (struct route *)realloc(cfg->routes, (size_t)(cfg->route_count + 1) * sizeof(struct route));
    if (!tmp) return -1;
    cfg->routes = tmp;
    cfg->routes[cfg->route_count] = r;
    cfg->route_count++;
    return 0;
}

/*
 * Splits "HOST:PORT" into two owned-by-caller substrings (mutates admin_spec
 * in place, like add_route_from_spec). Used for --admin CONTROL_HOST:PORT.
 */
static int split_host_port(char *spec, const char **host_out, const char **port_out)
{
    char *colon = strrchr(spec, ':');
    if (!colon || colon == spec || !colon[1]) return -1;
    *colon = '\0';
    *host_out = spec;
    *port_out = colon + 1;
    return 0;
}

static int parse_args(int argc, char **argv, struct config *cfg)
{
    int i;
    const char *legacy_listen_port = NULL;
    const char *legacy_connect_host = NULL;
    const char *legacy_connect_port = NULL;
    int route_flag_used = 0;
    char *admin_spec = NULL;
    int admin_cmd_flags = 0;

    memset(cfg, 0, sizeof(*cfg));
    cfg->insecure = 1; /* default to insecure for convenience */
    cfg->auto_cert = 1; /* auto-generate outstation cert/key by default */
    cfg->timeout_ms = 0;
    cfg->verbose = 0;
    cfg->log_keys = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "master") == 0) cfg->is_master = 1;
            else if (strcmp(argv[i], "outstation") == 0) cfg->is_master = 0;
            else return -1;
        } else if (strcmp(argv[i], "--listen-host") == 0 && i + 1 < argc) {
            cfg->listen_host = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            legacy_listen_port = argv[++i];
        } else if (strcmp(argv[i], "--connect-host") == 0 && i + 1 < argc) {
            legacy_connect_host = argv[++i];
        } else if (strcmp(argv[i], "--connect-port") == 0 && i + 1 < argc) {
            legacy_connect_port = argv[++i];
        } else if (strcmp(argv[i], "--route") == 0 && i + 1 < argc) {
            i++;
            if (add_route_from_spec(cfg, argv[i]) < 0) return -1;
            route_flag_used = 1;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cfg->cert_path = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            cfg->key_path = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            cfg->ca_path = argv[++i];
        } else if (strcmp(argv[i], "--insecure") == 0) {
            cfg->insecure = 1;
        } else if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            long v;
            if (parse_long(argv[++i], &v) < 0 || v < 0 || v > INT_MAX) return -1;
            cfg->timeout_ms = (int)v;
        } else if (strcmp(argv[i], "--verify-peer") == 0) {
            cfg->verify_peer = 1;
            cfg->insecure = 0;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            cfg->verbose = 1;
        } else if (strcmp(argv[i], "--log-keys") == 0) {
            cfg->log_keys = 1;
            cfg->verbose = 1;
        } else if (strcmp(argv[i], "--ml-kem") == 0) {
            cfg->use_ml_kem_512 = 1;
        } else if (strcmp(argv[i], "--control-host") == 0 && i + 1 < argc) {
            cfg->control_host = argv[++i];
        } else if (strcmp(argv[i], "--control-port") == 0 && i + 1 < argc) {
            cfg->control_port = argv[++i];
        } else if (strcmp(argv[i], "--announce-to") == 0 && i + 1 < argc) {
            i++;
            if (split_host_port(argv[i], &cfg->announce_admin_host, &cfg->announce_admin_port) < 0) return -1;
        } else if (strcmp(argv[i], "--announce-host") == 0 && i + 1 < argc) {
            cfg->announce_host = argv[++i];
        } else if (strcmp(argv[i], "--admin") == 0 && i + 1 < argc) {
            cfg->admin_mode = 1;
            admin_spec = argv[++i];
        } else if (strcmp(argv[i], "--add") == 0 && i + 1 < argc) {
            cfg->admin_cmd = ADMIN_CMD_ADD;
            cfg->admin_add_spec = argv[++i];
            admin_cmd_flags++;
        } else if (strcmp(argv[i], "--remove") == 0 && i + 1 < argc) {
            char *end = NULL;
            long v;
            i++;
            v = strtol(argv[i], &end, 10);
            if (!end || *end || v < 0) return -1;
            cfg->admin_remove_id = (int)v;
            cfg->admin_cmd = ADMIN_CMD_REMOVE;
            admin_cmd_flags++;
        } else if (strcmp(argv[i], "--list") == 0) {
            cfg->admin_cmd = ADMIN_CMD_LIST;
            admin_cmd_flags++;
        } else if (strcmp(argv[i], "--help") == 0) {
            return -1;
        } else {
            return -1;
        }
    }

    if (cfg->admin_mode) {
        if (!admin_spec || admin_cmd_flags != 1) return -1;
        if (split_host_port(admin_spec, &cfg->admin_host, &cfg->admin_port) < 0) return -1;
        return 0;
    }
    if (admin_cmd_flags) return -1; /* --add/--remove/--list only make sense with --admin */
    if (cfg->announce_admin_host && cfg->is_master) return -1; /* self-registration only makes sense for outstations */

    if (route_flag_used) {
        if (legacy_listen_port || legacy_connect_host || legacy_connect_port) return -1;
        if (cfg->route_count == 0) return -1;
        /* --listen-host may appear anywhere relative to --route; apply it to all routes now. */
        for (i = 0; i < cfg->route_count; i++) cfg->routes[i].listen_host = cfg->listen_host;
    } else {
        struct route *tmp;
        if (!legacy_listen_port || !legacy_connect_host || !legacy_connect_port) return -1;
        tmp = (struct route *)malloc(sizeof(struct route));
        if (!tmp) return -1;
        tmp[0].id = 0;
        tmp[0].listen_host = cfg->listen_host;
        tmp[0].listen_port = legacy_listen_port;
        tmp[0].connect_host = legacy_connect_host;
        tmp[0].connect_port = legacy_connect_port;
        cfg->routes = tmp;
        cfg->route_count = 1;
    }

    /* Server needs either --cert/--key or auto-generated certs (outstation only). */
    if (!cfg->is_master) {
        if ((!cfg->cert_path || !cfg->key_path) && !cfg->auto_cert) return -1;
    }

    return 0;
}

static void openssl_init(void)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

static void openssl_cleanup(void)
{
    EVP_cleanup();
}

static void print_ssl_error(const char *what)
{
    fprintf(stderr, "%s failed\n", what);
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "  %s\n", buf);
    }
}

static void print_name(const char *label, const X509_NAME *name)
{
    if (!name) {
        printf("%s: <null>\n", label);
        return;
    }
    char *s = X509_NAME_oneline(name, NULL, 0);
    if (s) {
        printf("%s: %s\n", label, s);
        OPENSSL_free(s);
    } else {
        printf("%s: <oneline-failed>\n", label);
    }
}

static void print_cert_details(const char *label, X509 *cert)
{
    if (!cert) {
        printf("%s: <none>\n", label);
        return;
    }

    printf("%s\n", label);
    print_name("  subject", X509_get_subject_name(cert));
    print_name("  issuer", X509_get_issuer_name(cert));

    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    if (serial) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
        if (bn) {
            char *hex = BN_bn2hex(bn);
            if (hex) {
                printf("  serial(hex): %s\n", hex);
                OPENSSL_free(hex);
            }
            BN_free(bn);
        }
    }
}

static int tls_configure_ctx_as_client(SSL_CTX *ctx, const struct config *cfg)
{
    /* Configure ML-KEM-512 (post-quantum) key exchange if requested */
    if (cfg->use_ml_kem_512) {
        /* Set TLS groups to prefer ML-KEM-512 for key encapsulation.
         * MLKEM512 is the NIST-standardized post-quantum KEM (FIPS 203).
         * This requires OpenSSL 3.2+ with ML-KEM support enabled. */
        if (SSL_CTX_set1_groups_list(ctx, "MLKEM512") != 1) {
            print_ssl_error("SSL_CTX_set1_groups_list(MLKEM512)");
            fprintf(stderr, "Note: ML-KEM-512 requires OpenSSL 3.2+ with ML-KEM support\n");
            return -1;
        }
        if (cfg->verbose) {
            printf("Configured ML-KEM-512 (post-quantum) key exchange\n");
        }
    } else {
        /* Set TLS groups to prefer X25519 for key encapsulation.*/
        if (SSL_CTX_set1_groups_list(ctx, "X25519") != 1) {
            print_ssl_error("SSL_CTX_set1_groups_list(X25519)");
            return -1;
        }
        if (cfg->verbose) {
            printf("Configured ECDH key exchange\n");
        }
    }

    if (!cfg->insecure || cfg->verify_peer) {
        if (cfg->ca_path) {
            if (!SSL_CTX_load_verify_locations(ctx, cfg->ca_path, NULL)) return -1;
        } else {
            if (!SSL_CTX_set_default_verify_paths(ctx)) return -1;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    return 0;
}

static int generate_self_signed_cert(SSL_CTX *ctx)
{
    clock_t start = clock();
    /* Ephemeral self-signed cert for lab/testing. */
    int rc = -1;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    X509 *x509 = NULL;

    pkey = EVP_PKEY_new();
    if (!pkey) goto done;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) goto done;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) goto done;

    {
        BIGNUM *e_bn = NULL;
        e_bn = BN_new();
        if (!e_bn) goto done;
        if (!BN_set_word(e_bn, RSA_F4)) {
            BN_free(e_bn);
            goto done;
        }
        if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pctx, e_bn) <= 0) {
            BN_free(e_bn);
            goto done;
        }
        BN_free(e_bn);
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto done;

    x509 = X509_new();
    if (!x509) goto done;

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 60L * 60L);
    X509_set_version(x509, 2);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = (X509_NAME *)X509_get_subject_name(x509);
    if (!name) goto done;
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"TLS-Mesh Proxy", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);

    if (!X509_set_issuer_name(x509, name)) goto done;
    if (!X509_sign(x509, pkey, EVP_sha256())) goto done;

    if (SSL_CTX_use_certificate(ctx, x509) != 1) goto done;
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) goto done;
    if (!SSL_CTX_check_private_key(ctx)) goto done;

    rc = 0;

done:
    if (rc != 0) print_ssl_error("generate_self_signed_cert");
    if (x509) X509_free(x509);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pkey) EVP_PKEY_free(pkey);
    clock_t end = clock(); 
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("Generate self cert Time elapsed: %.2f milliseconds\n", time_taken);
    return rc;
}

static int tls_configure_ctx_as_server(SSL_CTX *ctx, const struct config *cfg)
{
    /* Configure ML-KEM-512 (post-quantum) key exchange if requested */
    if (cfg->use_ml_kem_512) {
        /* Set TLS groups to prefer ML-KEM-512 for key encapsulation.
         * MLKEM512 is the NIST-standardized post-quantum KEM (FIPS 203).
         * This requires OpenSSL 3.2+ with ML-KEM support enabled. */
        if (SSL_CTX_set1_groups_list(ctx, "MLKEM512") != 1) {
            print_ssl_error("SSL_CTX_set1_groups_list(MLKEM512)");
            fprintf(stderr, "Note: ML-KEM-512 requires OpenSSL 3.2+ with ML-KEM support\n");
            return -1;
        }
        if (cfg->verbose) {
            printf("Configured ML-KEM-512 (post-quantum) key exchange\n");
        }
    }

    if (cfg->cert_path && cfg->key_path) {
        if (SSL_CTX_use_certificate_file(ctx, cfg->cert_path, SSL_FILETYPE_PEM) <= 0) return -1;
        if (SSL_CTX_use_PrivateKey_file(ctx, cfg->key_path, SSL_FILETYPE_PEM) <= 0) return -1;
    } else {
        if (!cfg->auto_cert) return -1;
        if (generate_self_signed_cert(ctx) < 0) return -1;
    }

    if (!SSL_CTX_check_private_key(ctx)) return -1;

    if (!cfg->insecure || cfg->verify_peer) {
        if (cfg->ca_path) {
            if (!SSL_CTX_load_verify_locations(ctx, cfg->ca_path, NULL)) return -1;
        } else {
            if (!SSL_CTX_set_default_verify_paths(ctx)) return -1;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return 0;
}

static void print_tls_details(SSL *ssl, const struct config *cfg)
{
    if (!ssl || !cfg) return;
    if (!cfg->verbose && !cfg->log_keys) return;

    printf("\n=== TLS Details (%s) ===\n", cfg->is_master ? "master" : "outstation");
    printf("TLS version: %s\n", SSL_get_version(ssl) ? SSL_get_version(ssl) : "<unknown>");
    printf("Cipher suite: %s\n", SSL_get_cipher(ssl) ? SSL_get_cipher(ssl) : "<unknown>");
    printf("Verify result: %ld\n", SSL_get_verify_result(ssl));

    X509 *peer = SSL_get_peer_certificate(ssl);
    if (peer) {
        print_cert_details("Peer certificate", peer);
        if (cfg->log_keys) {
            BIO *b = BIO_new(BIO_s_mem());
            if (b) {
                PEM_write_bio_X509(b, peer);
                BUF_MEM *ptr = NULL;
                BIO_get_mem_ptr(b, &ptr);
                if (ptr && ptr->data && ptr->length > 0) {
                    printf("Peer certificate PEM (%ld bytes):\n%.*s\n",
                           (long)ptr->length, (int)ptr->length, ptr->data);
                }
                BIO_free(b);
            }
        }
        X509_free(peer);
    } else {
        printf("Peer certificate: <none>\n");
    }

    X509 *local = SSL_get_certificate(ssl);
    if (local) {
        print_cert_details("Local certificate", local);
        if (cfg->log_keys) {
            BIO *b = BIO_new(BIO_s_mem());
            if (b) {
                PEM_write_bio_X509(b, local);
                BUF_MEM *ptr = NULL;
                BIO_get_mem_ptr(b, &ptr);
                if (ptr && ptr->data && ptr->length > 0) {
                    printf("Local certificate PEM (%ld bytes):\n%.*s\n",
                           (long)ptr->length, (int)ptr->length, ptr->data);
                }
                BIO_free(b);
            }
        }
        X509_free(local);
    }

    SSL_SESSION *sess = SSL_get_session(ssl);
    if (sess) {
        printf("Session reusable: %d\n", SSL_SESSION_is_resumable(sess));
    } else {
        printf("Session: <none>\n");
    }

    if (cfg->log_keys) {
        printf("log_keys enabled: TLS randoms (sensitive)\n");
        unsigned char cr[SSL3_RANDOM_SIZE];
        unsigned char sr[SSL3_RANDOM_SIZE];
        if (SSL_get_client_random(ssl, cr, sizeof(cr)) == 1) {
            printf("Client random (hex): ");
            for (size_t i = 0; i < sizeof(cr); i++) printf("%02X", cr[i]);
            printf("\n");
        }
        if (SSL_get_server_random(ssl, sr, sizeof(sr)) == 1) {
            printf("Server random (hex): ");
            for (size_t i = 0; i < sizeof(sr); i++) printf("%02X", sr[i]);
            printf("\n");
        }
    }

    printf("=== End TLS Details ===\n\n");
}

static int tls_handshake(SSL *ssl, const struct config *cfg)
{
    if (cfg->timeout_ms > 0) {
        struct timeval tv;
        tv.tv_sec = cfg->timeout_ms / 1000;
        tv.tv_usec = (cfg->timeout_ms % 1000) * 1000;
#ifdef _WIN32
        socket_t fd = SSL_get_fd(ssl);
        setsockopt((SOCKET)fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        setsockopt((SOCKET)fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
        socket_t fd = SSL_get_fd(ssl);
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    }

    int rc;
    clock_t start = clock();
    if (cfg->is_master) rc = SSL_connect(ssl);
    else rc = SSL_accept(ssl);
    clock_t end = clock(); 
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("tls handshake Time elapsed: %.2f milliseconds\n", time_taken);
    if (rc != 1) {
        print_ssl_error(cfg->is_master ? "SSL_connect" : "SSL_accept");
        return -1;
    }
    printf("Negotiated group: %s\n", SSL_get0_group_name(ssl));
    return 0;
}

static void log_bytes(const char *label, int n)
{
    if (n < 0) printf("%s: <error>\n", label);
    else printf("%s: %d bytes\n", label, n);
}

/*
 * Record packet size statistics. Allocates or expands the array as needed.
 */
static int record_packet_size(uint64_t **sizes, uint64_t *count, uint64_t *capacity, uint64_t size)
{
    uint64_t new_capacity;
    uint64_t *temp;

    if (*count >= *capacity) {
        new_capacity = (*capacity == 0) ? 256 : *capacity * 2;
        temp = (uint64_t *)realloc(*sizes, new_capacity * sizeof(uint64_t));
        if (!temp) return -1;
        *sizes = temp;
        *capacity = new_capacity;
    }
    (*sizes)[*count] = size;
    (*count)++;
    return 0;
}

/*
 * Compare function for qsort.
 */
static int compare_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

/*
 * Calculate statistics from a sorted array of packet sizes.
 */
static void calculate_stats(const uint64_t *sizes, uint64_t count,
                            uint64_t *min_out, uint64_t *max_out,
                            double *avg_out, double *median_out,
                            double *p50_out, double *p95_out, double *p99_out)
{
    uint64_t i, total = 0;
    uint64_t idx_50, idx_95, idx_99;
    double mean, variance = 0, stdev;

    if (count == 0) {
        *min_out = *max_out = 0;
        *avg_out = *median_out = *p50_out = *p95_out = *p99_out = 0;
        return;
    }

    *min_out = sizes[0];
    *max_out = sizes[count - 1];

    for (i = 0; i < count; i++) total += sizes[i];
    *avg_out = mean = (double)total / count;

    /* Median is P50 */
    idx_50 = count / 2;
    *median_out = (count % 2 == 0)
        ? ((double)sizes[idx_50 - 1] + (double)sizes[idx_50]) / 2.0
        : (double)sizes[idx_50];
    *p50_out = *median_out;

    /* P95 and P99 percentiles */
    idx_95 = (uint64_t)(count * 0.95);
    if (idx_95 >= count) idx_95 = count - 1;
    *p95_out = (double)sizes[idx_95];

    idx_99 = (uint64_t)(count * 0.99);
    if (idx_99 >= count) idx_99 = count - 1;
    *p99_out = (double)sizes[idx_99];

    /* Standard deviation */
    for (i = 0; i < count; i++) {
        double diff = (double)sizes[i] - mean;
        variance += diff * diff;
    }
    stdev = sqrt(variance / count);
    (void)stdev;  /* Avoid unused warning if not printed */
}

/*
 * Print a comprehensive statistics report for relay traffic.
 */
static void print_stats_report(struct channel *ch)
{
    uint64_t *plain_sorted = NULL, *enc_sorted = NULL;
    uint64_t min_p, max_p, min_e, max_e;
    double avg_p, median_p, p50_p, p95_p, p99_p;
    double avg_e, median_e, p50_e, p95_e, p99_e;
    uint64_t total_plain = 0, total_enc = 0, i;

    log_lock();
    printf("\n\n========== Packet Statistics Report (route %d) =========="
           "\n", ch->route_id);

    if (ch->plaintext_count == 0 && ch->encrypted_count == 0) {
        printf("No packet data collected.\n");
        log_unlock();
        return;
    }

    /* Calculate plaintext statistics */
    if (ch->plaintext_count > 0) {
        plain_sorted = (uint64_t *)malloc(ch->plaintext_count * sizeof(uint64_t));
        if (plain_sorted) {
            memcpy(plain_sorted, ch->plaintext_sizes, ch->plaintext_count * sizeof(uint64_t));
            qsort(plain_sorted, ch->plaintext_count, sizeof(uint64_t), compare_u64);
            for (i = 0; i < ch->plaintext_count; i++) total_plain += plain_sorted[i];
            calculate_stats(plain_sorted, ch->plaintext_count,
                            &min_p, &max_p, &avg_p, &median_p, &p50_p, &p95_p, &p99_p);
        }
    }

    /* Calculate encrypted statistics */
    if (ch->encrypted_count > 0) {
        enc_sorted = (uint64_t *)malloc(ch->encrypted_count * sizeof(uint64_t));
        if (enc_sorted) {
            memcpy(enc_sorted, ch->encrypted_sizes, ch->encrypted_count * sizeof(uint64_t));
            qsort(enc_sorted, ch->encrypted_count, sizeof(uint64_t), compare_u64);
            for (i = 0; i < ch->encrypted_count; i++) total_enc += enc_sorted[i];
            calculate_stats(enc_sorted, ch->encrypted_count,
                            &min_e, &max_e, &avg_e, &median_e, &p50_e, &p95_e, &p99_e);
        }
    }

    printf("\nPlaintext Packets:\n");
    printf("  Count:         %" PRIu64 "\n", ch->plaintext_count);
    printf("  Total bytes:   %" PRIu64 "\n", total_plain);
    if (plain_sorted) {
        printf("  Min:           %" PRIu64 " bytes\n", min_p);
        printf("  Max:           %" PRIu64 " bytes\n", max_p);
        printf("  Average:       %.2f bytes\n", avg_p);
        printf("  Median (P50):  %.2f bytes\n", median_p);
        printf("  P95:           %.2f bytes\n", p95_p);
        printf("  P99:           %.2f bytes\n", p99_p);
    }

    printf("\nEncrypted Packets:\n");
    printf("  Count:         %" PRIu64 "\n", ch->encrypted_count);
    printf("  Total bytes:   %" PRIu64 "\n", total_enc);
    if (enc_sorted) {
        printf("  Min:           %" PRIu64 " bytes\n", min_e);
        printf("  Max:           %" PRIu64 " bytes\n", max_e);
        printf("  Average:       %.2f bytes\n", avg_e);
        printf("  Median (P50):  %.2f bytes\n", median_e);
        printf("  P95:           %.2f bytes\n", p95_e);
        printf("  P99:           %.2f bytes\n", p99_e);
    }

    printf("\nEncryption Overhead:\n");
    if (total_plain > 0) {
        printf("  Overhead ratio: %.2f%% (encrypted/plaintext)\n",
               100.0 * (double)total_enc / (double)total_plain);
    }

    printf("\n==========================================\n\n");

    free(plain_sorted);
    free(enc_sorted);
    log_unlock();
}

/*
 * Free allocated statistics arrays.
 */
static void free_stats(struct channel *ch)
{
    free(ch->plaintext_sizes);
    free(ch->encrypted_sizes);
    ch->plaintext_sizes = NULL;
    ch->encrypted_sizes = NULL;
    ch->plaintext_count = 0;
    ch->encrypted_count = 0;
    ch->plaintext_capacity = 0;
    ch->encrypted_capacity = 0;
}

/*
 * volatile int *stop, when non-NULL, lets another thread (e.g. an admin REMOVE
 * of this route) ask the relay to exit promptly: the select() timeout is
 * capped at 1 second so *stop is polled regularly even if timeout_ms is 0
 * (block-forever).
 */
static int relay_loop(struct channel *ch, int timeout_ms, const struct config *cfg, volatile int *stop)
{
    unsigned char plain_buf[BUF_SIZE];
    unsigned char tls_buf[BUF_SIZE];

    uint64_t plain_recv_calls = 0;
    uint64_t plain_send_calls = 0;
    uint64_t tls_sslwrite_calls = 0;
    uint64_t tls_sslread_calls = 0;

    /* “messages received” counters + statistics over receive-chunk sizes */
    uint64_t plain_recv_msgs = 0; /* recv() chunks with n > 0 from plaintext side */
    uint64_t tls_recv_msgs = 0;   /* SSL_read() chunks with r > 0 from TLS side */

    uint64_t plain_recv_bytes_total = 0;
    uint64_t tls_recv_bytes_total = 0;

    uint64_t plain_recv_bytes_min = 0;
    uint64_t plain_recv_bytes_max = 0;
    uint64_t tls_recv_bytes_min = 0;
    uint64_t tls_recv_bytes_max = 0;

    uint64_t plain_to_tls_bytes = 0;   /* plaintext recv bytes fed into SSL_write */
    uint64_t tls_out_bytes = 0;        /* SSL_write bytes written */
    uint64_t tls_in_bytes = 0;         /* SSL_read returned bytes */
    uint64_t tls_to_plain_bytes = 0;  /* plain send bytes */

    int plain_open = 1;
    int tls_open = 1;

    while (plain_open && tls_open) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ch->plain_sock, &rfds);
        FD_SET(ch->tcp_secure_sock, &rfds);
        socket_t maxfd = ch->plain_sock > ch->tcp_secure_sock ? ch->plain_sock : ch->tcp_secure_sock;

        struct timeval tv;
        struct timeval *tvp = NULL;
        if (timeout_ms > 0) {
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            tvp = &tv;
        } else if (stop) {
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            tvp = &tv;
        }

        if (stop && *stop) return 0;
        int sel = select((int)maxfd + 1, &rfds, NULL, NULL, tvp);
        if (sel < 0) {
            perror("select");
            return -1;
        }
        if (sel == 0) continue;

        if (FD_ISSET(ch->plain_sock, &rfds)) {
            int n = (int)recv(ch->plain_sock, (char *)plain_buf, sizeof(plain_buf), 0);
            plain_recv_calls++;
            if (cfg->verbose) {
                printf("\n[relay] plaintext recv() -> %d bytes\n", n);
            }
            if (n <= 0) {
                plain_open = 0;
                break;
            }

            plain_recv_msgs++;
            plain_recv_bytes_total += (uint64_t)n;
            if (plain_recv_msgs == 1) {
                plain_recv_bytes_min = (uint64_t)n;
                plain_recv_bytes_max = (uint64_t)n;
            } else {
                if ((uint64_t)n < plain_recv_bytes_min) plain_recv_bytes_min = (uint64_t)n;
                if ((uint64_t)n > plain_recv_bytes_max) plain_recv_bytes_max = (uint64_t)n;
            }

            /* Record plaintext packet size statistics */
            if (record_packet_size(&ch->plaintext_sizes, &ch->plaintext_count,
                                  &ch->plaintext_capacity, (uint64_t)n) < 0) {
                fprintf(stderr, "failed to record plaintext packet size\n");
                return -1;
            }

            plain_to_tls_bytes += (uint64_t)n;

            int off = 0;
            while (off < n) {
                tls_sslwrite_calls++;
                clock_t start = clock();
                int w = SSL_write(ch->ssl, plain_buf + off, (int)(n - off));
                clock_t end = clock(); 
                double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
                printf("SSL write Time elapsed: %.2f milliseconds\n", time_taken);
                if (w <= 0) {
                    int err = SSL_get_error(ch->ssl, w);
                    if (cfg->verbose) {
                        printf("[relay] SSL_write error: w=%d SSL_get_error=%d\n", w, err);
                    }
                    return -1;
                }

                if (cfg->verbose) {
                    printf("[relay] SSL_write() <- %d plaintext bytes, wrote %d bytes\n", (int)(n - off), w);
                }

                tls_out_bytes += (uint64_t)w;
                off += w;
            }
        }

        if (FD_ISSET(ch->tcp_secure_sock, &rfds)) {
            clock_t start2 = clock();
            int r = SSL_read(ch->ssl, tls_buf, sizeof(tls_buf));
            clock_t end2 = clock(); 
            double time_taken = ((double)(end2 - start2) / CLOCKS_PER_SEC) * 1000.0;
            printf("SSL_read Time elapsed: %.2f milliseconds\n", time_taken);
            tls_sslread_calls++;
            if (cfg->verbose) {
                printf("\n[relay] SSL_read() -> %d bytes\n", r);
            }
            if (r <= 0) {
                int err = SSL_get_error(ch->ssl, r);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    tls_open = 0;
                    break;
                }
                if (cfg->verbose) {
                    printf("[relay] SSL_read error: r=%d SSL_get_error=%d\n", r, err);
                }
                return -1;
            }

            tls_recv_msgs++;
            tls_recv_bytes_total += (uint64_t)r;
            if (tls_recv_msgs == 1) {
                tls_recv_bytes_min = (uint64_t)r;
                tls_recv_bytes_max = (uint64_t)r;
            } else {
                if ((uint64_t)r < tls_recv_bytes_min) tls_recv_bytes_min = (uint64_t)r;
                if ((uint64_t)r > tls_recv_bytes_max) tls_recv_bytes_max = (uint64_t)r;
            }

            tls_in_bytes += (uint64_t)r;

            /* Record encrypted packet size statistics */
            if (record_packet_size(&ch->encrypted_sizes, &ch->encrypted_count,
                                  &ch->encrypted_capacity, (uint64_t)r) < 0) {
                fprintf(stderr, "failed to record encrypted packet size\n");
                return -1;
            }

            int off = 0;
            while (off < r) {
                plain_send_calls++;
                int w = (int)send(ch->plain_sock, (const char *)tls_buf + off, r - off, 0);
                if (w <= 0) return -1;

                if (cfg->verbose) {
                    printf("[relay] send() -> %d bytes\n", w);
                }

                tls_to_plain_bytes += (uint64_t)w;
                off += w;
            }
        }
    }

    double avg_plain_recv = plain_recv_calls
                                ? (double)plain_to_tls_bytes / plain_recv_calls
                                : 0.0;

    double avg_plain_send = plain_send_calls
                                ? (double)tls_to_plain_bytes / plain_send_calls
                                : 0.0;

    double avg_ssl_write = tls_sslwrite_calls
                               ? (double)tls_out_bytes / tls_sslwrite_calls
                               : 0.0;

    double avg_ssl_read = tls_sslread_calls
                              ? (double)tls_in_bytes / tls_sslread_calls
                              : 0.0;

    printf("\n========== Relay Byte Summary =========="
           "\nplain recv() calls: %llu"
           "\nplain send() calls: %llu"
           "\nSSL_write() calls: %llu"
           "\nSSL_read() calls:  %llu"

           "\n\nplain_to_tls_bytes (recv): %llu"
           "\n  Average bytes/recv():      %.2f"

           "\n\ntls_out_bytes (SSL_write): %llu"
           "\n  Average bytes/SSL_write(): %.2f"

           "\n\ntls_in_bytes (SSL_read): %llu"
           "\n  Average bytes/SSL_read():  %.2f"

           "\n\ntls_to_plain_bytes (send): %llu"
           "\n  Average bytes/send():      %.2f"

           "\n========================================\n",
           (unsigned long long)plain_recv_calls,
           (unsigned long long)plain_send_calls,
           (unsigned long long)tls_sslwrite_calls,
           (unsigned long long)tls_sslread_calls,

           (unsigned long long)plain_to_tls_bytes,
           avg_plain_recv,

           (unsigned long long)tls_out_bytes,
           avg_ssl_write,

           (unsigned long long)tls_in_bytes,
           avg_ssl_read,

           (unsigned long long)tls_to_plain_bytes,
           avg_plain_send);

    return 0;
}

static void teardown_channel(struct channel *ch)
{
    if (ch->ssl) SSL_shutdown(ch->ssl);
    if (ch->ssl) SSL_free(ch->ssl);
    if (ch->ssl_ctx) SSL_CTX_free(ch->ssl_ctx);
    if (ch->plain_sock != INVALID_SOCKET) CLOSESOCK(ch->plain_sock);
    if (ch->tcp_secure_sock != INVALID_SOCKET) CLOSESOCK(ch->tcp_secure_sock);
}

/*
 * Live, dynamically-manageable route state (see the matching type in
 * SAv6_proxy.c for the full rationale). Heap-allocated with a stable address
 * because a running thread holds a pointer to it for its whole lifetime, and
 * the admin control channel can add/remove slots at runtime.
 */
struct route_slot {
    int id;
    char *listen_host;   /* owned; NULL means listen on all interfaces */
    char *listen_port;   /* owned */
    char *connect_host;  /* owned */
    char *connect_port;  /* owned */
    int is_master;
    const struct config *cfg; /* shared, read-only: cert/key/CA/TLS settings */
    volatile int stop;   /* set by an admin REMOVE to ask the thread to exit */
    thread_t thread;
};

static mutex_t g_routes_mutex;
static struct route_slot **g_routes = NULL;
static int g_route_count = 0;
static int g_route_capacity = 0;
static int g_next_route_id = 0;

static char *dup_or_null(const char *s)
{
    return s ? strdup(s) : NULL;
}

static struct route_slot *route_slot_new(const char *listen_host, const char *listen_port,
                                          const char *connect_host, const char *connect_port,
                                          int is_master, const struct config *cfg)
{
    struct route_slot *rs = (struct route_slot *)calloc(1, sizeof(*rs));
    if (!rs) return NULL;
    rs->listen_host = dup_or_null(listen_host);
    rs->listen_port = strdup(listen_port);
    rs->connect_host = strdup(connect_host);
    rs->connect_port = strdup(connect_port);
    rs->is_master = is_master;
    rs->cfg = cfg;
    if ((listen_host && !rs->listen_host) || !rs->listen_port || !rs->connect_host || !rs->connect_port) {
        free(rs->listen_host);
        free(rs->listen_port);
        free(rs->connect_host);
        free(rs->connect_port);
        free(rs);
        return NULL;
    }
    return rs;
}

static void route_slot_free(struct route_slot *rs)
{
    if (!rs) return;
    free(rs->listen_host);
    free(rs->listen_port);
    free(rs->connect_host);
    free(rs->connect_port);
    free(rs);
}

static int registry_add(struct route_slot *rs)
{
    mtx_lock(&g_routes_mutex);
    rs->id = g_next_route_id++;
    if (g_route_count == g_route_capacity) {
        int newcap = g_route_capacity ? g_route_capacity * 2 : 4;
        struct route_slot **tmp = (struct route_slot **)realloc(g_routes, (size_t)newcap * sizeof(*tmp));
        if (!tmp) {
            mtx_unlock(&g_routes_mutex);
            return -1;
        }
        g_routes = tmp;
        g_route_capacity = newcap;
    }
    g_routes[g_route_count++] = rs;
    mtx_unlock(&g_routes_mutex);
    return rs->id;
}

static struct route_slot *registry_take(int id)
{
    int i;
    struct route_slot *rs = NULL;
    mtx_lock(&g_routes_mutex);
    for (i = 0; i < g_route_count; i++) {
        if (g_routes[i]->id == id) {
            rs = g_routes[i];
            g_routes[i] = g_routes[g_route_count - 1];
            g_route_count--;
            break;
        }
    }
    mtx_unlock(&g_routes_mutex);
    return rs;
}

static char *registry_render_list(void)
{
    int i;
    size_t cap = 256, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    buf[0] = '\0';

    mtx_lock(&g_routes_mutex);
    for (i = 0; i < g_route_count; i++) {
        struct route_slot *rs = g_routes[i];
        char line[320];
        int n = snprintf(line, sizeof(line), "%d %s %s -> %s:%s\n", rs->id,
                          rs->is_master ? "master" : "outstation", rs->listen_port,
                          rs->connect_host, rs->connect_port);
        if (n < 0) continue;
        if (len + (size_t)n + 1 > cap) {
            char *tmp;
            while (len + (size_t)n + 1 > cap) cap *= 2;
            tmp = (char *)realloc(buf, cap);
            if (!tmp) break;
            buf = tmp;
        }
        memcpy(buf + len, line, (size_t)n + 1);
        len += (size_t)n;
    }
    mtx_unlock(&g_routes_mutex);
    return buf;
}

/*
 * Detects a local outbound IPv4 address by "connecting" a UDP socket to a
 * fixed public address (no packet is actually sent for UDP connect(), it
 * just picks a route) and reading back the local endpoint the OS would use.
 * Used as the default --announce-host when none is given.
 */
static int detect_local_ip(char *buf, size_t buf_len)
{
    socket_t s;
    struct sockaddr_in addr, local;
    socklen_t local_len = sizeof(local);
    int ok = -1;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    if (inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr) == 1 &&
        connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
        getsockname(s, (struct sockaddr *)&local, &local_len) == 0 &&
        inet_ntop(AF_INET, &local.sin_addr, buf, (socklen_t)buf_len)) {
        ok = 0;
    }
    CLOSESOCK(s);
    return ok;
}

/*
 * Self-registration: sends a remote admin control channel the exact same ADD
 * command `--admin ... --add` would, so an outstation route doesn't have to
 * be added to its master by hand. See SAv6_proxy.c's announce_route for the
 * full rationale; this is the same protocol and design.
 */
static void announce_route(const char *admin_host, const char *admin_port,
                           const char *announce_host_cfg, int route_id, const char *route_listen_port)
{
    char detected[64];
    const char *announce_host = announce_host_cfg;
    char cmd[300];
    char resp[256];
    int attempt;

    if (!announce_host) {
        announce_host = (detect_local_ip(detected, sizeof(detected)) == 0) ? detected : "127.0.0.1";
    }
    snprintf(cmd, sizeof(cmd), "ADD %s:%s:%s\n", route_listen_port, announce_host, route_listen_port);

    for (attempt = 0; attempt < 5; attempt++) {
        socket_t s = connect_tcp(admin_host, admin_port);
        if (s != INVALID_SOCKET) {
            if (send_all(s, cmd, strlen(cmd)) == 0) {
                int n = recv(s, resp, sizeof(resp) - 1, 0);
                if (n > 0) {
                    resp[n] = '\0';
                    log_lock();
                    printf("[route %d] self-registration with master %s:%s: %s", route_id, admin_host, admin_port, resp);
                    if (n == 0 || resp[n - 1] != '\n') putchar('\n');
                    log_unlock();
                    CLOSESOCK(s);
                    return;
                }
            }
            CLOSESOCK(s);
        }
        if (attempt < 4) {
#ifdef _WIN32
            Sleep(2000);
#else
            sleep(2);
#endif
        }
    }
    log_lock();
    fprintf(stderr,
            "[route %d] self-registration with master %s:%s failed after retries; add it manually with:\n"
            "  ./TLS_proxy --admin %s:%s --add %s:%s:%s\n",
            route_id, admin_host, admin_port,
            admin_host, admin_port, route_listen_port, announce_host, route_listen_port);
    log_unlock();
}

static THREAD_RET THREAD_CALL master_route_thread(void *arg);
static THREAD_RET THREAD_CALL outstation_route_thread(void *arg);

static int start_route(struct route_slot *rs)
{
    return thread_create(&rs->thread, rs->is_master ? master_route_thread : outstation_route_thread, rs);
}

/*
 * Master-side route thread: binds this route's listen port once, then serves
 * plaintext clients forever, pairing each with a fresh TLS connection to this
 * route's outstation-side proxy. accept() is polled with a short timeout
 * (instead of blocking indefinitely) so rs->stop is noticed promptly if an
 * admin REMOVE command retires this route.
 */
static THREAD_RET THREAD_CALL master_route_thread(void *arg)
{
    struct route_slot *rs = (struct route_slot *)arg;
    const struct config *cfg = rs->cfg;
    socket_t listener;

    listener = listen_tcp(rs->listen_host, rs->listen_port);
    if (listener == INVALID_SOCKET) {
        log_lock();
        fprintf(stderr, "[route %d] failed to listen on %s:%s\n",
                rs->id, rs->listen_host ? rs->listen_host : "*", rs->listen_port);
        log_unlock();
        return 0;
    }
    log_lock();
    printf("[route %d] TLS-mesh master: waiting for plaintext station on %s:%s (-> TLS peer %s:%s)\n",
           rs->id, rs->listen_host ? rs->listen_host : "*", rs->listen_port,
           rs->connect_host, rs->connect_port);
    log_unlock();

    while (!rs->stop) {
        fd_set rfds;
        struct timeval tv;
        struct channel ch;
        socket_t accepted;

        FD_ZERO(&rfds);
        FD_SET(listener, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select((int)listener + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
        if (rs->stop) break;

        accepted = accept(listener, NULL, NULL);
        if (accepted == INVALID_SOCKET) continue;

        memset(&ch, 0, sizeof(ch));
        ch.is_master = 1;
        ch.route_id = rs->id;
        ch.plain_sock = accepted;
        ch.tcp_secure_sock = INVALID_SOCKET;

        ch.tcp_secure_sock = connect_tcp(rs->connect_host, rs->connect_port);
        if (ch.tcp_secure_sock == INVALID_SOCKET) {
            log_lock();
            fprintf(stderr, "[route %d] failed to connect TLS server at %s:%s\n",
                    rs->id, rs->connect_host, rs->connect_port);
            log_unlock();
            teardown_channel(&ch);
            continue;
        }

        ch.ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ch.ssl_ctx || tls_configure_ctx_as_client(ch.ssl_ctx, cfg) < 0) {
            log_lock();
            fprintf(stderr, "[route %d] ", rs->id);
            print_ssl_error("tls_configure_ctx_as_client");
            log_unlock();
            teardown_channel(&ch);
            continue;
        }
        ch.ssl = SSL_new(ch.ssl_ctx);
        if (!ch.ssl) {
            teardown_channel(&ch);
            continue;
        }
        SSL_set_fd(ch.ssl, (int)ch.tcp_secure_sock);

        log_lock();
        printf("[route %d] TLS-mesh master: performing TLS handshake to %s:%s\n",
               rs->id, rs->connect_host, rs->connect_port);
        log_unlock();

        if (tls_handshake(ch.ssl, cfg) == 0) {
            log_lock();
            printf("[route %d] TLS-mesh master: TLS handshake complete; relaying plaintext bytes\n", rs->id);
            log_unlock();
            print_tls_details(ch.ssl, cfg);
            relay_loop(&ch, cfg->timeout_ms, cfg, &rs->stop);
        }

        teardown_channel(&ch);
        print_stats_report(&ch);
        free_stats(&ch);
        if (!rs->stop) {
            log_lock();
            printf("[route %d] session ended; waiting for next plaintext station connection\n", rs->id);
            log_unlock();
        }
    }
    log_lock();
    printf("[route %d] route stopped\n", rs->id);
    log_unlock();
    return 0;
}

/*
 * Outstation-side route thread: binds this route's TLS listen port once,
 * then serves incoming TLS clients forever, pairing each with a fresh
 * connection to this route's local plaintext SAv5 device.
 */
static THREAD_RET THREAD_CALL outstation_route_thread(void *arg)
{
    struct route_slot *rs = (struct route_slot *)arg;
    const struct config *cfg = rs->cfg;
    socket_t listener;

    listener = listen_tcp(rs->listen_host, rs->listen_port);
    if (listener == INVALID_SOCKET) {
        log_lock();
        fprintf(stderr, "[route %d] failed to listen on %s:%s\n",
                rs->id, rs->listen_host ? rs->listen_host : "*", rs->listen_port);
        log_unlock();
        return 0;
    }
    log_lock();
    printf("[route %d] TLS-mesh outstation: waiting for TLS clients on %s:%s (-> local SAv5 %s:%s)\n",
           rs->id, rs->listen_host ? rs->listen_host : "*", rs->listen_port,
           rs->connect_host, rs->connect_port);
    log_unlock();

    if (cfg->announce_admin_host && cfg->announce_admin_port) {
        announce_route(cfg->announce_admin_host, cfg->announce_admin_port, cfg->announce_host, rs->id, rs->listen_port);
    }

    while (!rs->stop) {
        fd_set rfds;
        struct timeval tv;
        struct channel ch;
        socket_t accepted;

        FD_ZERO(&rfds);
        FD_SET(listener, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select((int)listener + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
        if (rs->stop) break;

        accepted = accept(listener, NULL, NULL);
        if (accepted == INVALID_SOCKET) continue;

        memset(&ch, 0, sizeof(ch));
        ch.is_master = 0;
        ch.route_id = rs->id;
        ch.tcp_secure_sock = accepted;
        ch.plain_sock = INVALID_SOCKET;

        ch.plain_sock = connect_tcp(rs->connect_host, rs->connect_port);
        if (ch.plain_sock == INVALID_SOCKET) {
            log_lock();
            fprintf(stderr, "[route %d] failed to connect local plaintext station at %s:%s\n",
                    rs->id, rs->connect_host, rs->connect_port);
            log_unlock();
            teardown_channel(&ch);
            continue;
        }

        ch.ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (!ch.ssl_ctx || tls_configure_ctx_as_server(ch.ssl_ctx, cfg) < 0) {
            log_lock();
            fprintf(stderr, "[route %d] ", rs->id);
            print_ssl_error("tls_configure_ctx_as_server");
            log_unlock();
            teardown_channel(&ch);
            continue;
        }
        ch.ssl = SSL_new(ch.ssl_ctx);
        if (!ch.ssl) {
            teardown_channel(&ch);
            continue;
        }
        SSL_set_fd(ch.ssl, (int)ch.tcp_secure_sock);

        log_lock();
        printf("[route %d] TLS-mesh outstation: performing TLS handshake\n", rs->id);
        log_unlock();

        if (tls_handshake(ch.ssl, cfg) == 0) {
            log_lock();
            printf("[route %d] TLS-mesh outstation: TLS handshake complete; relaying plaintext bytes\n", rs->id);
            log_unlock();
            print_tls_details(ch.ssl, cfg);
            relay_loop(&ch, cfg->timeout_ms, cfg, &rs->stop);
        }

        teardown_channel(&ch);
        print_stats_report(&ch);
        free_stats(&ch);
        if (!rs->stop) {
            log_lock();
            printf("[route %d] session ended; waiting for next TLS client connection\n", rs->id);
            log_unlock();
        }
    }
    log_lock();
    printf("[route %d] route stopped\n", rs->id);
    log_unlock();
    return 0;
}

/*
 * Adds a route from an admin "ADD LISTEN_PORT:CONNECT_HOST:CONNECT_PORT"
 * command: inherits this process's mode/cert/TLS settings via cfg.
 */
static int admin_add(const struct config *cfg, char *spec, char *resp, size_t resp_cap)
{
    char *first_colon, *last_colon;
    struct route_slot *rs;

    first_colon = strchr(spec, ':');
    last_colon = strrchr(spec, ':');
    if (!first_colon || first_colon == last_colon ||
        first_colon == spec || !first_colon[1] || !last_colon[1]) {
        snprintf(resp, resp_cap, "ERR bad spec, expected LISTEN_PORT:CONNECT_HOST:CONNECT_PORT\n");
        return -1;
    }
    *first_colon = '\0';
    *last_colon = '\0';

    rs = route_slot_new(cfg->listen_host, spec, first_colon + 1, last_colon + 1, cfg->is_master, cfg);
    if (!rs) {
        snprintf(resp, resp_cap, "ERR out of memory\n");
        return -1;
    }
    if (registry_add(rs) < 0) {
        route_slot_free(rs);
        snprintf(resp, resp_cap, "ERR failed to register route\n");
        return -1;
    }
    if (start_route(rs) < 0) {
        registry_take(rs->id);
        route_slot_free(rs);
        snprintf(resp, resp_cap, "ERR failed to start route thread\n");
        return -1;
    }
    log_lock();
    printf("[route %d] added by admin command (%s -> %s:%s)\n", rs->id, rs->listen_port, rs->connect_host, rs->connect_port);
    log_unlock();
    snprintf(resp, resp_cap, "OK %d\n", rs->id);
    return 0;
}

static int admin_remove(int id, char *resp, size_t resp_cap)
{
    struct route_slot *rs = registry_take(id);
    if (!rs) {
        snprintf(resp, resp_cap, "ERR no such route %d\n", id);
        return -1;
    }
    rs->stop = 1;
    thread_join(rs->thread);
    route_slot_free(rs);
    snprintf(resp, resp_cap, "OK\n");
    return 0;
}

static int recv_line(socket_t s, char *buf, size_t cap)
{
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        int r = recv(s, &c, 1, 0);
        if (r <= 0) break;
        if (c == '\n') break;
        if (c != '\r') buf[n++] = c;
    }
    buf[n] = '\0';
    return (int)n;
}

struct control_ctx {
    const struct config *cfg;
    const char *control_host;
    const char *control_port;
};

/*
 * Admin control channel: a simple newline-delimited text protocol, one
 * command per connection (ADD/REMOVE/LIST). See SAv6_proxy.c's control_thread
 * for the full rationale; this is the same protocol and design.
 */
static THREAD_RET THREAD_CALL control_thread(void *arg)
{
    struct control_ctx *cc = (struct control_ctx *)arg;
    socket_t listener = listen_tcp(cc->control_host, cc->control_port);
    if (listener == INVALID_SOCKET) {
        log_lock();
        fprintf(stderr, "[control] failed to listen on %s:%s\n",
                cc->control_host ? cc->control_host : "*", cc->control_port);
        log_unlock();
        return 0;
    }
    log_lock();
    printf("[control] admin channel listening on %s:%s (ADD/REMOVE/LIST)\n",
           cc->control_host ? cc->control_host : "*", cc->control_port);
    log_unlock();

    for (;;) {
        socket_t conn = accept(listener, NULL, NULL);
        char line[256];
        char resp[256];
        int n;
        if (conn == INVALID_SOCKET) continue;
        n = recv_line(conn, line, sizeof(line));
        if (n <= 0) {
            CLOSESOCK(conn);
            continue;
        }

        if (strncmp(line, "ADD ", 4) == 0) {
            admin_add(cc->cfg, line + 4, resp, sizeof(resp));
            send_all(conn, resp, strlen(resp));
        } else if (strncmp(line, "REMOVE ", 7) == 0) {
            admin_remove(atoi(line + 7), resp, sizeof(resp));
            send_all(conn, resp, strlen(resp));
        } else if (strcmp(line, "LIST") == 0) {
            char *listing = registry_render_list();
            if (listing) {
                send_all(conn, listing, strlen(listing));
                free(listing);
            }
            send_all(conn, ".\n", 2);
        } else {
            const char *e = "ERR unknown command (use ADD/REMOVE/LIST)\n";
            send_all(conn, e, strlen(e));
        }
        CLOSESOCK(conn);
    }
    return 0;
}

static int run_admin_client(const struct config *cfg)
{
    socket_t s;
    char cmd[300];
    char resp[4096];
    int n;

    s = connect_tcp(cfg->admin_host, cfg->admin_port);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "failed to connect to admin control channel at %s:%s\n", cfg->admin_host, cfg->admin_port);
        return 1;
    }
    if (cfg->admin_cmd == ADMIN_CMD_ADD) {
        snprintf(cmd, sizeof(cmd), "ADD %s\n", cfg->admin_add_spec);
    } else if (cfg->admin_cmd == ADMIN_CMD_REMOVE) {
        snprintf(cmd, sizeof(cmd), "REMOVE %d\n", cfg->admin_remove_id);
    } else {
        snprintf(cmd, sizeof(cmd), "LIST\n");
    }
    if (send_all(s, cmd, strlen(cmd)) < 0) {
        fprintf(stderr, "failed to send admin command\n");
        CLOSESOCK(s);
        return 1;
    }
    while ((n = recv(s, resp, sizeof(resp) - 1, 0)) > 0) {
        resp[n] = '\0';
        fputs(resp, stdout);
    }
    CLOSESOCK(s);
    return 0;
}

int main(int argc, char **argv)
{
    struct config cfg;
    int i;

    if (parse_args(argc, argv, &cfg) < 0) {
        usage(argv[0]);
        return 2;
    }

    if (socket_init() != 0) {
        fprintf(stderr, "socket initialization failed\n");
        return 1;
    }

    if (cfg.admin_mode) {
        int rc = run_admin_client(&cfg);
        socket_done();
        return rc;
    }

    mutex_init(&g_log_mutex);
    mutex_init(&g_routes_mutex);
    openssl_init();

    printf("starting %d route%s in %s mode\n", cfg.route_count, cfg.route_count == 1 ? "" : "s",
           cfg.is_master ? "master" : "outstation");

    for (i = 0; i < cfg.route_count; i++) {
        struct route_slot *rs = route_slot_new(cfg.routes[i].listen_host, cfg.routes[i].listen_port,
                                                cfg.routes[i].connect_host, cfg.routes[i].connect_port,
                                                cfg.is_master, &cfg);
        if (!rs || registry_add(rs) < 0 || start_route(rs) < 0) {
            fprintf(stderr, "failed to start initial route %d\n", i);
            return 1;
        }
    }

    if (cfg.control_port) {
        struct control_ctx cc;
        thread_t control_tid;
        cc.cfg = &cfg;
        cc.control_host = cfg.control_host ? cfg.control_host : "127.0.0.1";
        cc.control_port = cfg.control_port;
        if (thread_create(&control_tid, control_thread, &cc) < 0) {
            fprintf(stderr, "failed to start admin control thread\n");
            return 1;
        }
        thread_join(control_tid); /* blocks forever; control_thread loops indefinitely */
    } else {
        int n;
        thread_t *tids;
        mtx_lock(&g_routes_mutex);
        n = g_route_count;
        tids = (thread_t *)malloc((size_t)(n > 0 ? n : 1) * sizeof(thread_t));
        for (i = 0; i < n; i++) tids[i] = g_routes[i]->thread;
        mtx_unlock(&g_routes_mutex);
        for (i = 0; i < n; i++) thread_join(tids[i]);
        free(tids);
    }

    free(cfg.routes);
    openssl_cleanup();
    socket_done();
    return 0;
}
