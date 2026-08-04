#include <errno.h>
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
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* OpenSSL's Windows binaries may use a different C runtime than this program.
 * Applink bridges FILE* operations used by PEM_read_*(). */
#ifdef _WIN32
#include <openssl/applink.c>
#endif

#define MAGIC "SAV6PXY1"
#define MAGIC_LEN 8
#define VERSION 1
#define ALG_ECDH_X25519 1
#define ALG_MLKEM512 2

#define MSG_CLIENT_HELLO 1
#define MSG_SERVER_HELLO 2
#define MSG_WRAPPED_SESSION 3
#define MSG_DATA 4
#define MSG_CLOSE 5
#define MSG_AUTH 6

#define SESSION_KEY_LEN 32
#define UPDATE_KEY_LEN 32
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define MAX_FRAME 65536u

/*
 * Protocol constants and role configuration.
 * The proxy can operate in two modes: master-side relay or outstation-side relay.
 * The master side accepts plaintext from a local SAv5 client and connects to the
 * secure proxy endpoint. The outstation side accepts the secure proxy connection
 * and connects to the local plaintext SAv5 server.
 */
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
    int use_ml_kem;
    const char *listen_host;
    struct route *routes;
    int route_count;
    uint64_t update_rekey_messages;
    uint64_t session_rekey_messages;
    /* Mutual certificate authentication for the proxy-to-proxy handshake. */
    const char *cert_path;
    const char *key_path;
    const char *ca_path;
    int no_auth; /* explicit lab-only opt-out of peer authentication */

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
    socket_t secure_sock;
    int is_master;
    int use_ml_kem;
    int route_id;
    unsigned char session_key[SESSION_KEY_LEN];
    unsigned char update_key[UPDATE_KEY_LEN];
    unsigned char send_nonce_prefix[4];
    uint64_t send_counter;
    uint64_t recv_counter;
    uint64_t outbound_data_messages;
    uint64_t messages_since_update_key;
    uint64_t messages_since_session_key;
    uint64_t update_rekey_messages;
    uint64_t session_rekey_messages;
    /* Packet statistics tracking */
    uint64_t *plaintext_sizes;  /* Array of plaintext packet sizes */
    uint64_t *encrypted_sizes;  /* Array of encrypted packet sizes */
    uint64_t plaintext_count;   /* Number of plaintext packets received */
    uint64_t encrypted_count;   /* Number of encrypted packets received */
    uint64_t plaintext_capacity;/* Allocated array size for plaintext */
    uint64_t encrypted_capacity;/* Allocated array size for encrypted */
};

/* Forward declarations: full definitions live with the other thread/mutex wrappers. */
static void log_lock(void);
static void log_unlock(void);

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

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage (single point-to-point route):\n"
        "  %s --mode master [--listen-host HOST] --listen-port PLAIN_PORT --connect-host PROXY_HOST --connect-port PROXY_PORT (--cert CERT.pem --key KEY.pem --ca CA.pem | --no-auth) [--ml-kem] [--update-rekey-messages N] [--session-rekey-messages M]\n"
        "  %s --mode outstation [--listen-host HOST] --listen-port PROXY_PORT --connect-host SAv5_HOST --connect-port SAv5_PORT (--cert CERT.pem --key KEY.pem --ca CA.pem | --no-auth) [--ml-kem] [--update-rekey-messages N] [--session-rekey-messages M]\n\n"
        "Usage (point-to-multipoint, one process serving several outstations):\n"
        "  %s --mode master [--listen-host HOST] --route PLAIN_PORT:PROXY_HOST:PROXY_PORT [--route ...] [--ml-kem] [--update-rekey-messages N] [--session-rekey-messages M]\n"
        "  %s --mode outstation [--listen-host HOST] --route PROXY_PORT:SAv5_HOST:SAv5_PORT [--route ...] [--ml-kem] [--update-rekey-messages N] [--session-rekey-messages M]\n\n"
        "Master mode listens for a local SAv5 client, then connects to the remote secure peer.\n"
        "Outstation mode listens for a secure peer, then connects to the local SAv5 program.\n"
        "Each --route is a full listen+connect pairing (its own thread, own session keys);\n"
        "repeat --route to serve multiple outstations from one master-side process, or to\n"
        "front multiple local devices from one outstation-side process. --route may be\n"
        "repeated instead of, but not mixed with, the single-route --listen-port/--connect-host/--connect-port flags.\n"
        "If --listen-host is omitted, the proxy listens on all local interfaces.\n"
        "Both peers authenticate with their --cert/--key and verify the peer against --ca.\n"
        "Use --no-auth only for local/lab compatibility testing; it disables peer authentication.\n"
        "Rekey intervals default to 0, which disables automatic rekeying, and apply to every route.\n"
        "A route's process keeps serving new connections after a session ends (reconnect-safe).\n\n"
        "Optional admin control channel (add/remove routes at runtime, no restart):\n"
        "  %s --mode ... --control-port PORT [--control-host HOST] ...   (server; HOST defaults to 127.0.0.1)\n"
        "  %s --admin CONTROL_HOST:CONTROL_PORT --add LISTEN_PORT:CONNECT_HOST:CONNECT_PORT\n"
        "  %s --admin CONTROL_HOST:CONTROL_PORT --remove ROUTE_ID\n"
        "  %s --admin CONTROL_HOST:CONTROL_PORT --list\n"
        "A new route added this way inherits the running process's mode/--ml-kem/rekey settings;\n"
        "only its listen/connect endpoints are specified. REMOVE stops that route's listener and\n"
        "any in-progress session (within about a second) without touching other routes.\n\n"
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

/*
 * Print a buffer in hex for debugging of keys, nonces, ciphertext, and tags.
 */
static void log_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;
    log_lock();
    printf("%s (%zu bytes): ", label, len);
    for (i = 0; i < len; i++) printf("%02X", buf[i]);
    putchar('\n');
    log_unlock();
}

/*
 * Emit a labeled step marker in console output for tracing handshake and relay progress.
 */
static void log_step(const char *label)
{
    log_lock();
    printf("\n=== %s ===\n", label);
    log_unlock();
}

/*
 * Initialize the platform socket subsystem if needed.
 * On Windows this starts Winsock; on Unix-like systems no initialization is required.
 */
static int socket_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    return 0;
#endif
}

/*
 * Cleanup platform socket state on Windows; no-op on Unix-like systems.
 */
static void socket_done(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

/*
 * Minimal cross-platform thread/mutex wrappers. Each route (one master<->outstation
 * pairing) runs its own persistent thread with its own struct channel, so the only
 * shared mutable state across threads is stdout, which log_lock/log_unlock protect
 * against interleaved multi-line hex dumps.
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

/*
 * Ensure a complete buffer is written on the socket. This is required because
 * send() may deliver fewer bytes than requested on a single call.
 */
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

/*
 * Read exactly `len` bytes from a socket, retrying until the requested amount
 * has been received or an error occurs.
 */
static int recv_all(socket_t s, void *buf, size_t len)
{
    unsigned char *p = (unsigned char *)buf;
    while (len > 0) {
        int n = recv(s, (char *)p, (int)len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/*
 * Send and receive 32-bit big-endian length values used in the framed protocol.
 */
static int send_u32(socket_t s, uint32_t v)
{
    uint32_t n = htonl(v);
    return send_all(s, &n, sizeof(n));
}

static int recv_u32(socket_t s, uint32_t *v)
{
    uint32_t n;
    if (recv_all(s, &n, sizeof(n)) < 0) return -1;
    *v = ntohl(n);
    return 0;
}

/*
 * Send a protocol frame with a one-byte message type, a 32-bit payload length,
 * and optional payload data.
 */
static int send_msg(socket_t s, uint8_t type, const void *payload, uint32_t len)
{
    clock_t start = clock();
    if (send_all(s, &type, 1) < 0) return -1;
    if (send_u32(s, len) < 0) return -1;
    if (len && send_all(s, payload, len) < 0) return -1;
    clock_t end = clock();
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("send_msg Time elapsed: %.2f milliseconds\n", time_taken);
    return 0;
}

/*
 * Receive a framed message and return its type and payload buffer. The caller
 * takes ownership of the allocated payload buffer.
 */
static int recv_msg(socket_t s, uint8_t *type, unsigned char **payload, uint32_t *len)
{
    clock_t start = clock();
    if (recv_all(s, type, 1) < 0) return -1;
    if (recv_u32(s, len) < 0) return -1;
    if (*len > MAX_FRAME + 1024u) return -1;
    *payload = NULL;
    if (*len) {
        *payload = (unsigned char *)malloc(*len);
        if (!*payload) return -1;
        if (recv_all(s, *payload, *len) < 0) {
            free(*payload);
            *payload = NULL;
            return -1;
        }
    }
    clock_t end = clock();
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("recv_msg Time elapsed: %.2f milliseconds\n", time_taken);
    return 0;
}

/*
 * Connect to a TCP peer by resolving the host and port and trying each
 * returned address until a connection succeeds.
 */
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

/*
 * Bind and listen on a TCP port. If host is NULL the socket listens on all
 * local addresses.
 */
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

/*
 * Derive a fixed-length update key from a shared secret using HKDF-SHA256.
 * The derived key is used to encrypt session key updates and to protect
 * subsequent data-plane traffic.
 */
static int hkdf_sha256(const unsigned char *secret, size_t secret_len,
                       const char *info, unsigned char out[UPDATE_KEY_LEN])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    const unsigned char salt[] = "SAv6-proxy-update-key";
    int ok = 0;

    if (!ctx) return -1;
    clock_t start2 = clock();
    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt) - 1) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, secret_len) <= 0) goto done;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char *)info, strlen(info)) <= 0) goto done;
    {
        size_t out_len = UPDATE_KEY_LEN;
        if (EVP_PKEY_derive(ctx, out, &out_len) <= 0 || out_len != UPDATE_KEY_LEN) goto done;
    }
    clock_t end2 = clock();
    ok = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    double time_taken2 = ((double)(end2 - start2) / CLOCKS_PER_SEC) * 1000.0;
    printf("EVP_PKEY_derive Time elapsed: %.2f milliseconds\n", time_taken2);
    return ok ? 0 : -1;
}

/*
 * Generate a fresh X25519 key pair for the ECDH-based update-key handshake.
 */
static EVP_PKEY *make_x25519_key(void)
{
    clock_t start = clock();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    clock_t end = clock(); 
done:
    EVP_PKEY_CTX_free(ctx);
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("x25519 generation Time elapsed: %.2f milliseconds\n", time_taken);
    return key;
}

/*
 * Extract the raw public key bytes from an EVP_PKEY into a newly allocated buffer.
 */
static int get_raw_pub(EVP_PKEY *key, unsigned char **pub, size_t *pub_len)
{
    if (EVP_PKEY_get_raw_public_key(key, NULL, pub_len) <= 0) return -1;
    *pub = (unsigned char *)malloc(*pub_len);
    if (!*pub) return -1;
    if (EVP_PKEY_get_raw_public_key(key, *pub, pub_len) <= 0) {
        free(*pub);
        *pub = NULL;
        return -1;
    }
    return 0;
}

/*
 * Extract the raw private key bytes from an EVP_PKEY into a newly allocated buffer.
 * The raw private key is used only for logging/debug visibility and is immediately cleansed.
 */
static int get_raw_priv(EVP_PKEY *key, unsigned char **priv, size_t *priv_len)
{
    if (EVP_PKEY_get_raw_private_key(key, NULL, priv_len) <= 0) return -1;
    *priv = (unsigned char *)malloc(*priv_len);
    if (!*priv) return -1;
    if (EVP_PKEY_get_raw_private_key(key, *priv, priv_len) <= 0) {
        free(*priv);
        *priv = NULL;
        return -1;
    }
    return 0;
}

/*
 * Derive the shared secret with a peer X25519 public key, then HKDF it into
 * the runtime update key used for AES key wrapping.
 */
static int derive_x25519(EVP_PKEY *priv, const unsigned char *peer_pub, size_t peer_pub_len,
                         unsigned char update_key[UPDATE_KEY_LEN])
{
    clock_t start = clock();
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *secret = NULL;
    size_t secret_len = 0;
    int ok = 0;

    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, peer_pub_len);
    if (!peer) goto done;
    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) goto done;
    clock_t start2 = clock();
    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto done;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) goto done;
    secret = (unsigned char *)malloc(secret_len);
    if (!secret) goto done;
    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) goto done;
    clock_t end2 = clock();
    double time_taken2 = ((double)(end2 - start2) / CLOCKS_PER_SEC) * 1000.0;
    log_hex("ECDH raw shared secret", secret, secret_len);
    clock_t start3 = clock();
    if (hkdf_sha256(secret, secret_len, "ECDH-X25519", update_key) < 0) goto done;
    clock_t end3 = clock();
    double time_taken3 = ((double)(end3 - start3) / CLOCKS_PER_SEC) * 1000.0;
    log_hex("ECDH HKDF-derived Update Key", update_key, UPDATE_KEY_LEN);
    ok = 1;
done:
    if (secret) OPENSSL_cleanse(secret, secret_len);
    free(secret);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    clock_t end = clock();
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("EVP_PKEY_derive Time elapsed: %.2f milliseconds\n", time_taken2);
    printf("hkdf_sha256 Time elapsed: %.2f milliseconds\n", time_taken3);
    printf("derive_x25519 full length Time elapsed: %.2f milliseconds\n", time_taken);
    return ok ? 0 : -1;
}

/*
 * Wrap the session key using AES-KW with the previously established update key.
 * The wrapped session key is sent as a protected WRAPPED_SESSION frame.
 */
/*
 * Wrap the newly generated AES session key using the currently active update key.
 * The wrapped output is sent to the remote peer as a protected session-key frame.
 */
static int aes_wrap_key(const unsigned char update_key[UPDATE_KEY_LEN],
                        const unsigned char session_key[SESSION_KEY_LEN],
                        unsigned char **wrapped, int *wrapped_len)
{
    clock_t start = clock();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    *wrapped = (unsigned char *)malloc(SESSION_KEY_LEN + 8);
    if (!ctx || !*wrapped) goto fail;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, update_key, NULL) <= 0) goto fail;
    if (EVP_EncryptUpdate(ctx, *wrapped, &len, session_key, SESSION_KEY_LEN) <= 0) goto fail;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, *wrapped + total, &len) <= 0) goto fail;
    total += len;
    *wrapped_len = total;
    EVP_CIPHER_CTX_free(ctx);
    clock_t end = clock(); 
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("wrap session key using AES key wrap Time elapsed: %.2f milliseconds\n", time_taken);
    return 0;
fail:
    EVP_CIPHER_CTX_free(ctx);
    free(*wrapped);
    *wrapped = NULL;
    return -1;
}

/*
 * Unwrap a protected session key received from the master, using the active
 * update key to recover the AES-256-GCM key for decrypting data frames.
 */
static int aes_unwrap_key(const unsigned char update_key[UPDATE_KEY_LEN],
                          const unsigned char *wrapped, int wrapped_len,
                          unsigned char session_key[SESSION_KEY_LEN])
{
    clock_t start = clock();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    unsigned char out[SESSION_KEY_LEN + 8];
    int ok = 0;

    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, update_key, NULL) <= 0) goto done;
    if (EVP_DecryptUpdate(ctx, out, &len, wrapped, wrapped_len) <= 0) goto done;
    total = len;
    if (EVP_DecryptFinal_ex(ctx, out + total, &len) <= 0) goto done;
    total += len;
    if (total != SESSION_KEY_LEN) goto done;
    memcpy(session_key, out, SESSION_KEY_LEN);
    ok = 1;
done:
    OPENSSL_cleanse(out, sizeof(out));
    EVP_CIPHER_CTX_free(ctx);
    clock_t end = clock(); 
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("unwrap session key using AES key wrap Time elapsed: %.2f milliseconds\n", time_taken);
    return ok ? 0 : -1;
}

/*
 * Construct a 12-byte AES-GCM nonce from a 4-byte prefix and an 8-byte counter.
 * The prefix is role-specific so each direction uses a distinct nonce namespace.
 */
static void build_nonce(const unsigned char prefix[4], uint64_t counter,
                        unsigned char nonce[GCM_NONCE_LEN])
{
    memcpy(nonce, prefix, 4);
    nonce[4] = (unsigned char)(counter >> 56);
    nonce[5] = (unsigned char)(counter >> 48);
    nonce[6] = (unsigned char)(counter >> 40);
    nonce[7] = (unsigned char)(counter >> 32);
    nonce[8] = (unsigned char)(counter >> 24);
    nonce[9] = (unsigned char)(counter >> 16);
    nonce[10] = (unsigned char)(counter >> 8);
    nonce[11] = (unsigned char)counter;
}

static int establish_outstation_update_key(struct channel *ch, const unsigned char *payload, uint32_t len);
static int receive_outstation_session_key(struct channel *ch, const unsigned char *wrapped, uint32_t wrapped_len);

/*
 * Encrypt a plaintext message using the current session key and send it as
 * a MSG_DATA frame over the secure channel.
 */
static int send_encrypted(struct channel *ch, const unsigned char *plain, uint32_t plain_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char nonce[GCM_NONCE_LEN], tag[GCM_TAG_LEN];
    unsigned char *buf = NULL;
    int len = 0, total = 0;
    uint32_t payload_len;
    int ok = -1;

    clock_t start = clock();
    if (!ctx || plain_len > MAX_FRAME) goto done;
    build_nonce(ch->send_nonce_prefix, ch->send_counter++, nonce);
    buf = (unsigned char *)malloc(GCM_NONCE_LEN + plain_len + GCM_TAG_LEN);
    if (!buf) goto done;
    memcpy(buf, nonce, GCM_NONCE_LEN);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, ch->session_key, nonce) <= 0) goto done;
    if (EVP_EncryptUpdate(ctx, buf + GCM_NONCE_LEN, &len, plain, plain_len) <= 0) goto done;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, buf + GCM_NONCE_LEN + total, &len) <= 0) goto done;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) <= 0) goto done;
    memcpy(buf + GCM_NONCE_LEN + total, tag, GCM_TAG_LEN);
    payload_len = (uint32_t)(GCM_NONCE_LEN + total + GCM_TAG_LEN);
    clock_t end = clock(); 
    log_step("Encrypted outbound communication");
    printf("Plaintext bytes: %u\n", plain_len);
    log_hex("Plaintext", plain, plain_len);
    log_hex("AES-256-GCM nonce", nonce, GCM_NONCE_LEN);
    log_hex("AES-256-GCM ciphertext", buf + GCM_NONCE_LEN, (size_t)total);
    log_hex("AES-256-GCM tag", tag, GCM_TAG_LEN);
    printf("Sending encrypted frame payload bytes: %u\n", payload_len);
    ok = send_msg(ch->secure_sock, MSG_DATA, buf, payload_len);
    if (ok == 0) {
        ch->outbound_data_messages++;
        ch->messages_since_update_key++;
        ch->messages_since_session_key++;
    }
done:
    free(buf);
    EVP_CIPHER_CTX_free(ctx);
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("Send_encrypted Time elapsed: %.2f milliseconds\n", time_taken);
    return ok;
}

/*
 * Receive a secure frame from the peer, handle control frames such as
 * rekey and close notifications, and decrypt MSG_DATA frames to plaintext.
 */
static int recv_encrypted(struct channel *ch, unsigned char **plain, uint32_t *plain_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *payload = NULL;
    uint8_t type;
    uint32_t payload_len;
    int len = 0, total = 0;
    int ok = -1;

next_message:
    if (recv_msg(ch->secure_sock, &type, &payload, &payload_len) < 0) return -1;
    if (type == MSG_CLOSE) {
        printf("\nReceived encrypted close notification\n");
        free(payload);
        *plain = NULL;
        *plain_len = 0;
        return 1;
    }
    if (type == MSG_CLIENT_HELLO) {
        if (ch->is_master) goto done;
        log_step("Received runtime Update Key rekey request");
        if (establish_outstation_update_key(ch, payload, payload_len) < 0) goto done;
        free(payload);
        payload = NULL;
        goto next_message;
    }
    if (type == MSG_WRAPPED_SESSION) {
        if (ch->is_master) goto done;
        log_step("Received runtime Session Key rekey request");
        if (receive_outstation_session_key(ch, payload, payload_len) < 0) goto done;
        free(payload);
        payload = NULL;
        goto next_message;
    }
    clock_t start = clock();
    if (type != MSG_DATA || payload_len < GCM_NONCE_LEN + GCM_TAG_LEN) goto done;
    if (payload_len > MAX_FRAME + GCM_NONCE_LEN + GCM_TAG_LEN) goto done;
    *plain_len = payload_len - GCM_NONCE_LEN - GCM_TAG_LEN;
    *plain = (unsigned char *)malloc(*plain_len ? *plain_len : 1);
    if (!*plain) goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, ch->session_key, payload) <= 0) goto done;
    if (*plain_len) {
        if (EVP_DecryptUpdate(ctx, *plain, &len, payload + GCM_NONCE_LEN, *plain_len) <= 0) goto done;
        total = len;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
            payload + GCM_NONCE_LEN + *plain_len) <= 0) goto done;
    if (EVP_DecryptFinal_ex(ctx, *plain + total, &len) <= 0) goto done;
    clock_t end = clock(); 
    log_step("Decrypted inbound communication");
    printf("Encrypted frame payload bytes: %u\n", payload_len);
    log_hex("AES-256-GCM nonce", payload, GCM_NONCE_LEN);
    log_hex("AES-256-GCM ciphertext", payload + GCM_NONCE_LEN, *plain_len);
    log_hex("AES-256-GCM tag", payload + GCM_NONCE_LEN + *plain_len, GCM_TAG_LEN);
    log_hex("Decrypted plaintext", *plain, *plain_len);
    ch->recv_counter++;
    ch->messages_since_update_key++;
    ch->messages_since_session_key++;
    ok = 0;
done:
    if (ok < 0) {
        free(*plain);
        *plain = NULL;
        *plain_len = 0;
    }
    free(payload);
    EVP_CIPHER_CTX_free(ctx);
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("Receive_encrypted Time elapsed: %.2f milliseconds\n", time_taken);
    return ok;
}

/*
 * Send a framed hello message. The frame includes the protocol magic, version,
 * algorithm identifier, and an optional payload body.
 */
static int send_hello(socket_t s, uint8_t type, uint8_t alg,
                      const unsigned char *body, uint32_t body_len)
{
    unsigned char *p = (unsigned char *)malloc(MAGIC_LEN + 2 + body_len);
    int rc;
    if (!p) return -1;
    memcpy(p, MAGIC, MAGIC_LEN);
    p[MAGIC_LEN] = VERSION;
    p[MAGIC_LEN + 1] = alg;
    if (body_len) memcpy(p + MAGIC_LEN + 2, body, body_len);
    rc = send_msg(s, type, p, MAGIC_LEN + 2 + body_len);
    free(p);
    return rc;
}

/*
 * Convenience wrappers for the HELLO control messages used during the
 * secure handshake.
 */
static int send_client_hello(socket_t s, uint8_t alg, const unsigned char *body, uint32_t body_len)
{
    return send_hello(s, MSG_CLIENT_HELLO, alg, body, body_len);
}

static int send_server_hello(socket_t s, uint8_t alg, const unsigned char *body, uint32_t body_len)
{
    return send_hello(s, MSG_SERVER_HELLO, alg, body, body_len);
}

/* Authenticate a fresh key-establishment result.  The certificate and
 * signature travel together in MSG_AUTH; the signature covers the derived
 * update key, so an old proof cannot be replayed into another handshake. */
static int send_authentication(struct channel *ch, const struct config *cfg)
{
    FILE *cert_file = NULL, *key_file = NULL;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *der = NULL, *p, proof[sizeof("SAV6-AUTH-v1") + UPDATE_KEY_LEN];
    unsigned char *payload = NULL;
    size_t sig_len = 0;
    int der_len, ok = -1;
    clock_t start = clock();

    cert_file = fopen(cfg->cert_path, "rb");
    key_file = fopen(cfg->key_path, "rb");
    if (!cert_file || !key_file) goto done;
    cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    if (!cert || !key || X509_check_private_key(cert, key) != 1) goto done;
    der_len = i2d_X509(cert, NULL);
    if (der_len <= 0 || (uint32_t)der_len > MAX_FRAME) goto done;
    der = (unsigned char *)malloc((size_t)der_len);
    if (!der) goto done;
    p = der;
    if (i2d_X509(cert, &p) != der_len) goto done;
    proof[0] = ch->is_master ? 'M' : 'O';
    memcpy(proof + 1, "SAV6-AUTH-v1", sizeof("SAV6-AUTH-v1") - 1);
    memcpy(proof + sizeof("SAV6-AUTH-v1"), ch->update_key, UPDATE_KEY_LEN);
    {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        if (!md) goto done;
        if (EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key) != 1 ||
            EVP_DigestSign(md, NULL, &sig_len, proof, sizeof(proof)) != 1) {
            EVP_MD_CTX_free(md); goto done;
        }
        payload = (unsigned char *)malloc(4u + (size_t)der_len + sig_len);
        if (!payload || EVP_DigestSign(md, payload + 4 + der_len, &sig_len,
                                       proof, sizeof(proof)) != 1) {
            EVP_MD_CTX_free(md); goto done;
        }
        EVP_MD_CTX_free(md);
    }
    if (sig_len > MAX_FRAME - 4u - (uint32_t)der_len) goto done;
    { uint32_t n = htonl((uint32_t)der_len); memcpy(payload, &n, sizeof(n)); }
    memcpy(payload + 4, der, (size_t)der_len);
    if (send_msg(ch->secure_sock, MSG_AUTH, payload,
                 (uint32_t)(4u + (size_t)der_len + sig_len)) < 0) goto done;
    ok = 0;
done:
    if (cert_file) fclose(cert_file);
    if (key_file) fclose(key_file);
    EVP_PKEY_free(key);
    X509_free(cert);
    free(der);
    free(payload);
    clock_t end = clock();
    printf("SAv6 local certificate authentication Time elapsed: %.2f milliseconds\n",
           ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0);
    return ok;
}

static int verify_authentication(struct channel *ch, const struct config *cfg)
{
    uint8_t type;
    uint32_t len, cert_len_n, cert_len;
    unsigned char *payload = NULL, proof[sizeof("SAV6-AUTH-v1") + UPDATE_KEY_LEN];
    const unsigned char *p;
    X509 *cert = NULL;
    EVP_PKEY *peer_key = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *store_ctx = NULL;
    int ok = -1;

    if (recv_msg(ch->secure_sock, &type, &payload, &len) < 0 || type != MSG_AUTH || len < 5) goto done;
    clock_t start = clock();
    memcpy(&cert_len_n, payload, sizeof(cert_len_n));
    cert_len = ntohl(cert_len_n);
    if (cert_len == 0 || cert_len > len - 4 || len - 4 - cert_len == 0) goto done;
    p = payload + 4;
    cert = d2i_X509(NULL, &p, (long)cert_len);
    if (!cert || p != payload + 4 + cert_len) goto done;
    store = X509_STORE_new();
    store_ctx = X509_STORE_CTX_new();
    if (!store || !store_ctx || X509_STORE_load_locations(store, cfg->ca_path, NULL) != 1 ||
        X509_STORE_CTX_init(store_ctx, store, cert, NULL) != 1 ||
        X509_verify_cert(store_ctx) != 1) goto done;
    peer_key = X509_get_pubkey(cert);
    proof[0] = ch->is_master ? 'O' : 'M';
    memcpy(proof + 1, "SAV6-AUTH-v1", sizeof("SAV6-AUTH-v1") - 1);
    memcpy(proof + sizeof("SAV6-AUTH-v1"), ch->update_key, UPDATE_KEY_LEN);
    {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        if (!md) goto done;
        ok = peer_key && EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, peer_key) == 1 &&
             EVP_DigestVerify(md, payload + 4 + cert_len, len - 4 - cert_len,
                              proof, sizeof(proof)) == 1 ? 0 : -1;
        EVP_MD_CTX_free(md);
    }
done:
    free(payload);
    EVP_PKEY_free(peer_key);
    X509_STORE_CTX_free(store_ctx);
    X509_STORE_free(store);
    X509_free(cert);
    clock_t end = clock();
    printf("SAv6 peer certificate authentication Time elapsed: %.2f milliseconds\n",
           ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0);
    return ok;
}

/*
 * Parse the HELLO frame header and extract the negotiated algorithm and body payload.
 */
static int parse_hello(const unsigned char *p, uint32_t len, uint8_t *alg,
                       const unsigned char **body, uint32_t *body_len)
{
    if (len < MAGIC_LEN + 2) return -1;
    if (memcmp(p, MAGIC, MAGIC_LEN) != 0 || p[MAGIC_LEN] != VERSION) return -1;
    *alg = p[MAGIC_LEN + 1];
    *body = p + MAGIC_LEN + 2;
    *body_len = len - MAGIC_LEN - 2;
    return 0;
}

/*
 * Master initiates the ECDH update-key handshake, sends its X25519 public key,
 * and derives the shared update key after receiving the peer public key.
 */
static int ecdh_master_handshake(socket_t s, unsigned char update_key[UPDATE_KEY_LEN])
{
    EVP_PKEY *key = make_x25519_key();
    unsigned char *pub = NULL, *priv = NULL, *payload = NULL;
    size_t pub_len = 0, priv_len = 0;
    uint8_t type, alg;
    uint32_t len, body_len;
    const unsigned char *body;
    int ok = -1;

    log_step("ECDH master handshake");
    if (!key || get_raw_pub(key, &pub, &pub_len) < 0 ||
        get_raw_priv(key, &priv, &priv_len) < 0 || pub_len > UINT32_MAX) goto done;
    log_hex("Master X25519 private key", priv, priv_len);
    log_hex("Master X25519 public key", pub, pub_len);
    printf("Sending CLIENT_HELLO with X25519 public key\n");
    if (send_client_hello(s, ALG_ECDH_X25519, pub, (uint32_t)pub_len) < 0) goto done;
    if (recv_msg(s, &type, &payload, &len) < 0) goto done;
    if (type != MSG_SERVER_HELLO || parse_hello(payload, len, &alg, &body, &body_len) < 0) goto done;
    if (alg != ALG_ECDH_X25519) goto done;
    clock_t start = clock();
    ok = derive_x25519(key, body, body_len, update_key);
    clock_t end = clock();
    log_hex("Received outstation X25519 public key", body, body_len);
done:
    free(payload);
    if (priv) OPENSSL_cleanse(priv, priv_len);
    free(priv);
    free(pub);
    EVP_PKEY_free(key);
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("ECDH outstation handshake x25519 Time elapsed: %.2f milliseconds\n", time_taken);
    return ok;
}

/*
 * Outstation responds to an ECDH CLIENT_HELLO by generating its own key pair,
 * sending SERVER_HELLO, and deriving the shared update key.
 */
static int ecdh_outstation_handshake(socket_t s, const unsigned char *client_pub,
                                     uint32_t client_pub_len,
                                     unsigned char update_key[UPDATE_KEY_LEN])
{
    EVP_PKEY *key = make_x25519_key();
    unsigned char *pub = NULL, *priv = NULL;
    size_t pub_len = 0, priv_len = 0;
    int ok = -1;

    log_step("ECDH outstation handshake");
    log_hex("Received master X25519 public key", client_pub, client_pub_len);
    if (!key || get_raw_pub(key, &pub, &pub_len) < 0 ||
        get_raw_priv(key, &priv, &priv_len) < 0 || pub_len > UINT32_MAX) goto done;
    if (send_server_hello(s, ALG_ECDH_X25519, pub, (uint32_t)pub_len) < 0) goto done;
    clock_t start = clock();
    ok = derive_x25519(key, client_pub, client_pub_len, update_key);
    clock_t end = clock(); 
    log_hex("Outstation X25519 private key", priv, priv_len);
    log_hex("Outstation X25519 public key", pub, pub_len);
    printf("Sending SERVER_HELLO with X25519 public key\n");
done:
    if (priv) OPENSSL_cleanse(priv, priv_len);
    free(priv);
    free(pub);
    EVP_PKEY_free(key);
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("ECDH outstation handshake x25519 Time elapsed: %.2f milliseconds\n", time_taken);
    return ok;
}

/*
 * Master requests ML-KEM-512 from the peer, imports the returned public key,
 * performs encapsulation, and derives the shared update key from the secret.
 */
static int mlkem_master_handshake(socket_t s, unsigned char update_key[UPDATE_KEY_LEN])
{
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *payload = NULL;
    uint8_t type, alg;
    uint32_t len, body_len;
    const unsigned char *body;
    unsigned char *ciphertext = NULL, *secret = NULL;
    size_t ciphertext_len = 0, secret_len = 0;
    OSSL_PARAM params[2];
    int ok = -1;

    log_step("ML-KEM master handshake");
    printf("Sending CLIENT_HELLO requesting ML-KEM-512\n");
    if (send_client_hello(s, ALG_MLKEM512, NULL, 0) < 0) goto done;
    if (recv_msg(s, &type, &payload, &len) < 0) goto done;
    if (type != MSG_SERVER_HELLO || parse_hello(payload, len, &alg, &body, &body_len) < 0) goto done;
    if (alg != ALG_MLKEM512) goto done;

    clock_t start = clock();
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-512", NULL);
    if (!pctx || EVP_PKEY_fromdata_init(pctx) <= 0) goto done;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (void *)body, body_len);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata(pctx, &peer, EVP_PKEY_PUBLIC_KEY, params) <= 0) goto done;
    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL);
    if (!pctx || EVP_PKEY_encapsulate_init(pctx, NULL) <= 0) goto done;
    if (EVP_PKEY_encapsulate(pctx, NULL, &ciphertext_len, NULL, &secret_len) <= 0) goto done;
    ciphertext = (unsigned char *)malloc(ciphertext_len);
    secret = (unsigned char *)malloc(secret_len);
    if (!ciphertext || !secret) goto done;
    if (EVP_PKEY_encapsulate(pctx, ciphertext, &ciphertext_len, secret, &secret_len) <= 0) goto done;
    if (ciphertext_len > UINT32_MAX) goto done;
    if (send_msg(s, MSG_CLIENT_HELLO, ciphertext, (uint32_t)ciphertext_len) < 0) goto done;
    if (hkdf_sha256(secret, secret_len, "ML-KEM-512", update_key) < 0) goto done;
    clock_t end = clock(); 
    log_hex("ML-KEM ciphertext sent to outstation", ciphertext, ciphertext_len);
    log_hex("ML-KEM shared secret", secret, secret_len);
    log_hex("ML-KEM HKDF-derived Update Key", update_key, UPDATE_KEY_LEN);
    ok = 0;
done:
    if (secret) OPENSSL_cleanse(secret, secret_len);
    free(secret);
    free(ciphertext);
    free(payload);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(peer);
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("mlkem master handshake Time elapsed: %.2f milliseconds\n", time_taken);
    return ok;
}

/*
 * Outstation generates an ML-KEM-512 key pair, sends the public key, then
 * decapsulates the ciphertext received from the master to derive the shared key.
 */
static int mlkem_outstation_handshake(socket_t s, unsigned char update_key[UPDATE_KEY_LEN])
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *public_key = NULL, *secret = NULL;
    unsigned char *payload = NULL;
    uint8_t type;
    uint32_t len;
    size_t public_key_len = 0, secret_len = 0;
    int ok = -1;

    log_step("ML-KEM outstation handshake");
    clock_t start3 = clock();
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-512", NULL);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0) goto done;
    if (EVP_PKEY_keygen(pctx, &key) <= 0) goto done;
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        NULL, 0, &public_key_len) <= 0) goto done;
    public_key = (unsigned char *)malloc(public_key_len);
    if (!public_key) goto done;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        public_key, public_key_len, &public_key_len) <= 0) goto done;
    if (public_key_len > UINT32_MAX) goto done;
    clock_t end3 = clock();
    double time_taken3 = ((double)(end3 - start3) / CLOCKS_PER_SEC) * 1000.0;
    printf("generate ML-KEM private/public key Time elapsed: %.2f milliseconds\n", time_taken3);
    log_hex("Outstation ML-KEM-512 public key", public_key, public_key_len);
    printf("Sending SERVER_HELLO with ML-KEM-512 public key\n");
    if (send_server_hello(s, ALG_MLKEM512, public_key, (uint32_t)public_key_len) < 0) goto done;

    if (recv_msg(s, &type, &payload, &len) < 0) goto done;
    if (type != MSG_CLIENT_HELLO) goto done;
    log_hex("Received master ML-KEM ciphertext", payload, len);
    clock_t start2 = clock();
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!pctx || EVP_PKEY_decapsulate_init(pctx, NULL) <= 0) goto done;
    if (EVP_PKEY_decapsulate(pctx, NULL, &secret_len, payload, len) <= 0) goto done;
    secret = (unsigned char *)malloc(secret_len);
    if (!secret) goto done;
    if (EVP_PKEY_decapsulate(pctx, secret, &secret_len, payload, len) <= 0) goto done;
    clock_t end2 = clock();
    double time_taken2 = ((double)(end2 - start2) / CLOCKS_PER_SEC) * 1000.0;
    printf("EVP_PKEY_decapsulate Time elapsed: %.2f milliseconds\n", time_taken2);
    log_hex("ML-KEM shared secret", secret, secret_len);
    clock_t start = clock();
    if (hkdf_sha256(secret, secret_len, "ML-KEM-512", update_key) < 0) goto done;
    clock_t end = clock();
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("Derive Update Key from ML-KEM shared secret Time elapsed: %.2f milliseconds\n", time_taken);
    log_hex("ML-KEM HKDF-derived Update Key", update_key, UPDATE_KEY_LEN);
    ok = 0;
done:
    if (secret) OPENSSL_cleanse(secret, secret_len);
    free(secret);
    free(public_key);
    free(payload);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(key);
    return ok;
}

/*
 * Establish or re-establish the runtime update key on the master side.
 * This either performs X25519 ECDH or ML-KEM-512 based on the current flag.
 */
static int establish_master_update_key(struct channel *ch)
{
    unsigned char update_key[UPDATE_KEY_LEN];
    int rc;

    if (ch->use_ml_kem) {
        rc = mlkem_master_handshake(ch->secure_sock, update_key);
    } else {
        rc = ecdh_master_handshake(ch->secure_sock, update_key);
    }
    if (rc < 0) {
        OPENSSL_cleanse(update_key, sizeof(update_key));
        return -1;
    }
    memcpy(ch->update_key, update_key, UPDATE_KEY_LEN);
    ch->messages_since_update_key = 0;
    OPENSSL_cleanse(update_key, sizeof(update_key));
    return 0;
}

/*
 * Complete the outstation-side update-key handshake after receiving the
 * initial CLIENT_HELLO. The outstation chooses the algorithm requested by the
 * master, performs the corresponding handshake, and stores the derived update key.
 */
static int establish_outstation_update_key(struct channel *ch, const unsigned char *payload, uint32_t len)
{
    unsigned char update_key[UPDATE_KEY_LEN];
    uint8_t alg;
    uint32_t body_len;
    const unsigned char *body;
    int rc;

    if (parse_hello(payload, len, &alg, &body, &body_len) < 0) return -1;
    /* Outstation dynamically chooses algorithm based on master's request, not local config */
    if (alg == ALG_MLKEM512) {
        if (body_len != 0) return -1;
        rc = mlkem_outstation_handshake(ch->secure_sock, update_key);
    } else if (alg == ALG_ECDH_X25519) {
        rc = ecdh_outstation_handshake(ch->secure_sock, body, body_len, update_key);
    } else {
        return -1;
    }
    if (rc < 0) {
        OPENSSL_cleanse(update_key, sizeof(update_key));
        return -1;
    }
    memcpy(ch->update_key, update_key, UPDATE_KEY_LEN);
    ch->messages_since_update_key = 0;
    OPENSSL_cleanse(update_key, sizeof(update_key));
    return 0;
}

/*
 * Generate a fresh AES-256-GCM session key on the master and securely
 * transmit it to the outstation using the previously established update key.
 */
static int establish_master_session_key(struct channel *ch)
{
    unsigned char *wrapped = NULL;
    int wrapped_len = 0;
    int ok = -1;

    log_step("Master session key establishment");
    if (RAND_bytes(ch->session_key, SESSION_KEY_LEN) != 1) goto done;
    log_hex("Generated AES-256-GCM session key", ch->session_key, SESSION_KEY_LEN);
    if (aes_wrap_key(ch->update_key, ch->session_key, &wrapped, &wrapped_len) < 0) goto done;
    log_hex("AES Key Wrap output carrying session key", wrapped, (size_t)wrapped_len);
    printf("Sending WRAPPED_SESSION to outstation proxy\n");
    if (send_msg(ch->secure_sock, MSG_WRAPPED_SESSION, wrapped, (uint32_t)wrapped_len) < 0) goto done;
    ch->send_counter = 0;
    ch->messages_since_session_key = 0;
    ok = 0;
done:
    free(wrapped);
    return ok;
}

/*
 * Unwrap the session key delivered by the master using the currently active
 * update key and begin using it for AES-256-GCM traffic decryption.
 */
static int receive_outstation_session_key(struct channel *ch, const unsigned char *wrapped, uint32_t wrapped_len)
{
    log_step("Outstation session key establishment");
    log_hex("Received AES Key Wrap payload", wrapped, wrapped_len);
    if (aes_unwrap_key(ch->update_key, wrapped, (int)wrapped_len, ch->session_key) < 0) return -1;
    log_hex("Unwrapped AES-256-GCM session key", ch->session_key, SESSION_KEY_LEN);
    ch->recv_counter = 0;
    ch->messages_since_session_key = 0;
    return 0;
}

/*
 * Check if the master relay should trigger an automatic rekey based on the
 * configured frame thresholds. Only the master side manages automatic rekey.
 */
static int maybe_master_rekey(struct channel *ch)
{
    if (!ch->is_master) return 0;

    if (ch->update_rekey_messages &&
        ch->messages_since_update_key >= ch->update_rekey_messages) {
        log_step("Automatic Update Key rekey trigger");
        printf("Protected data frames since Update Key: %llu; threshold: %llu\n",
               (unsigned long long)ch->messages_since_update_key,
               (unsigned long long)ch->update_rekey_messages);
        if (establish_master_update_key(ch) < 0) return -1;
    }

    if (ch->session_rekey_messages &&
        ch->messages_since_session_key >= ch->session_rekey_messages) {
        log_step("Automatic Session Key rekey trigger");
        printf("Protected data frames since Session Key: %llu; threshold: %llu\n",
               (unsigned long long)ch->messages_since_session_key,
               (unsigned long long)ch->session_rekey_messages);
        if (establish_master_session_key(ch) < 0) return -1;
    }

    return 0;
}

static int master_handshake(struct channel *ch, const struct config *cfg)
{
    if (establish_master_update_key(ch) < 0) return -1;
    if (!cfg->no_auth &&
        (send_authentication(ch, cfg) < 0 || verify_authentication(ch, cfg) < 0)) return -1;
    return establish_master_session_key(ch);
}

/*
 * Perform the outstation side of the initial secure handshake.
 * The outstation first handles the CLIENT_HELLO, establishes the update key,
 * then receives and unwraps the wrapped session key.
 */
static int outstation_handshake(struct channel *ch, const struct config *cfg)
{
    clock_t start = clock();
    unsigned char *payload = NULL, *wrapped = NULL;
    uint8_t type;
    uint32_t len, wrapped_len;
    int ok = -1;

    if (recv_msg(ch->secure_sock, &type, &payload, &len) < 0) goto done;
    if (type != MSG_CLIENT_HELLO) goto done;
    if (establish_outstation_update_key(ch, payload, len) < 0) goto done;
    free(payload);
    payload = NULL;
    if (!cfg->no_auth &&
        (verify_authentication(ch, cfg) < 0 || send_authentication(ch, cfg) < 0)) goto done;
    if (recv_msg(ch->secure_sock, &type, &wrapped, &wrapped_len) < 0) goto done;
    if (type != MSG_WRAPPED_SESSION) goto done;
    if (receive_outstation_session_key(ch, wrapped, wrapped_len) < 0) goto done;
    clock_t end = clock();
    double time_taken = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("Outstation full handshake Time elapsed: %.2f milliseconds\n", time_taken);
    ok = 0;
done:
    free(payload);
    free(wrapped);
    return ok;
}

/*
 * Main relay loop: forward plaintext from the local endpoint to the secure peer
 * and decrypt/forward secure frames from the peer back to the local endpoint.
 */
/*
 * Relay plaintext<->secure traffic until the connection closes or *stop is set
 * by another thread (e.g. an admin REMOVE of this route). select() is polled
 * with a short timeout rather than blocked on indefinitely so *stop is noticed
 * promptly without needing to force-close sockets from another thread.
 */
static int relay(socket_t plain_sock, struct channel *ch, volatile int *stop)
{
    fd_set rfds;
    unsigned char buf[MAX_FRAME];
    int done = 0;

    while (!done) {
        struct timeval tv;
        int selr;
        socket_t maxfd = plain_sock > ch->secure_sock ? plain_sock : ch->secure_sock;
        if (stop && *stop) return 0;
        FD_ZERO(&rfds);
        FD_SET(plain_sock, &rfds);
        FD_SET(ch->secure_sock, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        selr = select((int)maxfd + 1, &rfds, NULL, NULL, &tv);
        if (selr < 0) return -1;
        if (selr == 0) continue;

        if (FD_ISSET(plain_sock, &rfds)) {
            int n = recv(plain_sock, (char *)buf, sizeof(buf), 0);
            if (n <= 0) {
                printf("\nPlaintext side closed; sending encrypted close notification\n");
                send_msg(ch->secure_sock, MSG_CLOSE, NULL, 0);
                done = 1;
            } else {
                printf("\nPlaintext -> secure: received %d plaintext bytes from local endpoint\n", n);
                /* Record plaintext packet size statistics */
                if (record_packet_size(&ch->plaintext_sizes, &ch->plaintext_count,
                                      &ch->plaintext_capacity, (uint64_t)n) < 0) {
                    fprintf(stderr, "failed to record plaintext packet size\n");
                    return -1;
                }
                if (maybe_master_rekey(ch) < 0) {
                    return -1;
                }
                if (send_encrypted(ch, buf, (uint32_t)n) < 0) {
                    return -1;
                }
            }
        }

        if (FD_ISSET(ch->secure_sock, &rfds)) {
            unsigned char *plain = NULL;
            uint32_t plain_len = 0;
            int rc = recv_encrypted(ch, &plain, &plain_len);
            if (rc == 1) {
                free(plain);
                done = 1;
            } else if (rc < 0) {
                free(plain);
                return -1;
            } else {
                printf("\nSecure -> plaintext: forwarding %u decrypted bytes to local endpoint\n", plain_len);
                /* Record encrypted packet size statistics (decrypted payload size) */
                if (record_packet_size(&ch->encrypted_sizes, &ch->encrypted_count,
                                      &ch->encrypted_capacity, (uint64_t)plain_len) < 0) {
                    fprintf(stderr, "failed to record encrypted packet size\n");
                    free(plain);
                    return -1;
                }
                if (send_all(plain_sock, plain, plain_len) < 0) {
                    free(plain);
                    return -1;
                }
                free(plain);
            }
        }
    }
    return 0;
}

/*
 * Parse an unsigned 64-bit integer from a command line argument.
 */
static int parse_u64_arg(const char *s, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;

    if (!s || !s[0]) return -1;
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno || *end) return -1;
    *out = (uint64_t)v;
    return 0;
}

/*
 * Append a route parsed from a "LISTEN_PORT:CONNECT_HOST:CONNECT_PORT" string
 * to cfg->routes, growing the array as needed. The connect host itself may not
 * contain a colon (IPv6 literals are not supported in this compact form); use
 * a hostname or IPv4 address.
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
    r.listen_host = cfg->listen_host;
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
 * Parse command-line arguments for proxy mode, host/port bindings, ML-KEM
 * selection, and optional rekey thresholds. Supports either a single legacy
 * point-to-point route (--listen-port/--connect-host/--connect-port) or one
 * or more repeatable --route LISTEN_PORT:CONNECT_HOST:CONNECT_PORT entries
 * for point-to-multipoint operation. The two forms cannot be mixed.
 */
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
    int mode_set = 0;
    const char *legacy_listen_port = NULL;
    const char *legacy_connect_host = NULL;
    const char *legacy_connect_port = NULL;
    int route_flag_used = 0;
    char *admin_spec = NULL;
    int admin_cmd_flags = 0; /* count of --add/--remove/--list seen, for mutual-exclusion check */

    memset(cfg, 0, sizeof(*cfg));
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "master") == 0) cfg->is_master = 1;
            else if (strcmp(argv[i], "outstation") == 0) cfg->is_master = 0;
            else return -1;
            mode_set = 1;
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            legacy_listen_port = argv[++i];
        } else if (strcmp(argv[i], "--listen-host") == 0 && i + 1 < argc) {
            cfg->listen_host = argv[++i];
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
        } else if (strcmp(argv[i], "--no-auth") == 0) {
            cfg->no_auth = 1;
        } else if (strcmp(argv[i], "--ml-kem") == 0) {
            cfg->use_ml_kem = 1;
        } else if (strcmp(argv[i], "--update-rekey-messages") == 0 && i + 1 < argc) {
            if (parse_u64_arg(argv[++i], &cfg->update_rekey_messages) < 0) return -1;
        } else if (strcmp(argv[i], "--session-rekey-messages") == 0 && i + 1 < argc) {
            if (parse_u64_arg(argv[++i], &cfg->session_rekey_messages) < 0) return -1;
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

    if (!mode_set) return -1;
    if (!cfg->no_auth && (!cfg->cert_path || !cfg->key_path || !cfg->ca_path)) return -1;
    if (cfg->announce_admin_host && cfg->is_master) return -1; /* self-registration only makes sense for outstations */
    if (route_flag_used) {
        if (legacy_listen_port || legacy_connect_host || legacy_connect_port) return -1;
        if (cfg->route_count == 0) return -1;
        /* --listen-host may appear anywhere relative to --route; apply it to all routes now. */
        for (i = 0; i < cfg->route_count; i++) cfg->routes[i].listen_host = cfg->listen_host;
        return 0;
    }
    if (!legacy_listen_port || !legacy_connect_host || !legacy_connect_port) return -1;

    {
        struct route *tmp = (struct route *)malloc(sizeof(struct route));
        if (!tmp) return -1;
        tmp[0].id = 0;
        tmp[0].listen_host = cfg->listen_host;
        tmp[0].listen_port = legacy_listen_port;
        tmp[0].connect_host = legacy_connect_host;
        tmp[0].connect_port = legacy_connect_port;
        cfg->routes = tmp;
        cfg->route_count = 1;
    }
    return 0;
}

/*
 * Live, dynamically-manageable route state. Unlike the read-only struct route
 * used to seed routes from the command line, a route_slot is heap-allocated
 * with a stable address (it is never moved by a realloc) because a running
 * thread holds a pointer to it for its whole lifetime, and the admin control
 * channel can add or remove slots at runtime while other routes keep going.
 */
struct route_slot {
    int id;
    char *listen_host;   /* owned; NULL means listen on all interfaces */
    char *listen_port;   /* owned */
    char *connect_host;  /* owned */
    char *connect_port;  /* owned */
    int is_master;
    int use_ml_kem;
    uint64_t update_rekey_messages;
    uint64_t session_rekey_messages;
    /* Self-registration (outstation routes only); see struct config for the
     * meaning of each field. announce_admin_host NULL means disabled. */
    char *announce_host;
    char *announce_admin_host;
    char *announce_admin_port;
    volatile int stop;   /* set by an admin REMOVE to ask the thread to exit */
    thread_t thread;
};

/*
 * Registry of live route_slots. Seeded at startup from the command line's
 * --route/legacy flags, and mutated afterwards by ADD/REMOVE/LIST admin
 * commands over the optional control socket. g_routes is an array of
 * pointers (not of structs) so growing it never invalidates a route_slot's
 * address.
 */
static mutex_t g_routes_mutex;
/* Immutable for the process lifetime; route threads use it for certificate
 * authentication while route topology remains independently mutable. */
static const struct config *g_auth_cfg;
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
                                          int is_master, int use_ml_kem,
                                          uint64_t update_rekey_messages, uint64_t session_rekey_messages,
                                          const char *announce_host, const char *announce_admin_host,
                                          const char *announce_admin_port)
{
    struct route_slot *rs = (struct route_slot *)calloc(1, sizeof(*rs));
    if (!rs) return NULL;
    rs->listen_host = dup_or_null(listen_host);
    rs->listen_port = strdup(listen_port);
    rs->connect_host = strdup(connect_host);
    rs->connect_port = strdup(connect_port);
    rs->is_master = is_master;
    rs->use_ml_kem = use_ml_kem;
    rs->update_rekey_messages = update_rekey_messages;
    rs->session_rekey_messages = session_rekey_messages;
    rs->announce_host = dup_or_null(announce_host);
    rs->announce_admin_host = dup_or_null(announce_admin_host);
    rs->announce_admin_port = dup_or_null(announce_admin_port);
    if ((listen_host && !rs->listen_host) || !rs->listen_port || !rs->connect_host || !rs->connect_port ||
        (announce_host && !rs->announce_host) ||
        (announce_admin_host && !rs->announce_admin_host) ||
        (announce_admin_port && !rs->announce_admin_port)) {
        free(rs->listen_host);
        free(rs->listen_port);
        free(rs->connect_host);
        free(rs->connect_port);
        free(rs->announce_host);
        free(rs->announce_admin_host);
        free(rs->announce_admin_port);
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
    free(rs->announce_host);
    free(rs->announce_admin_host);
    free(rs->announce_admin_port);
    free(rs);
}

/* Registers rs in the live registry and assigns it the next route id. */
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

/* Removes and returns the route_slot with the given id, if any; does not stop or join its thread. */
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

/* Renders the current registry as one "id role listen -> host:port" line per route, for LIST. */
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
 * be added to its master by hand. The master-side port requested is this
 * route's own listen port. Retries a few times, 2s apart, since the master
 * may not be up yet when an outstation starts; gives up with a clear log
 * message (including the equivalent manual command) if it never succeeds.
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
            "  ./%s --admin %s:%s --add %s:%s:%s\n",
            route_id, admin_host, admin_port,
            "SAv6_proxy", admin_host, admin_port, route_listen_port, announce_host, route_listen_port);
    log_unlock();
}

static THREAD_RET THREAD_CALL master_route_thread(void *arg);
static THREAD_RET THREAD_CALL outstation_route_thread(void *arg);

/* Spawns rs's thread according to its is_master flag. */
static int start_route(struct route_slot *rs)
{
    return thread_create(&rs->thread, rs->is_master ? master_route_thread : outstation_route_thread, rs);
}

/*
 * Master-side route thread: binds this route's listen port once, then serves
 * connections forever. Each accepted plaintext client is paired with a fresh
 * connection to this route's outstation-side proxy, handshaked, and relayed;
 * when that session ends the thread loops back to accept the next one, so a
 * master reconnecting (or a different DNP3 session) is handled without
 * restarting the process. accept() is polled with a short timeout (instead of
 * blocking indefinitely) so rs->stop is noticed promptly if an admin REMOVE
 * command retires this route.
 */
static THREAD_RET THREAD_CALL master_route_thread(void *arg)
{
    struct route_slot *rs = (struct route_slot *)arg;
    socket_t listener;

    listener = listen_tcp(rs->listen_host, rs->listen_port);
    if (listener == INVALID_SOCKET) {
        log_lock();
        fprintf(stderr, "[route %d] failed to listen on local/plain %s:%s\n",
                rs->id, rs->listen_host ? rs->listen_host : "*", rs->listen_port);
        log_unlock();
        return 0;
    }
    log_lock();
    printf("[route %d] master: waiting for local SAv5 connections on %s:%s (-> secure peer %s:%s)\n",
           rs->id, rs->listen_host ? rs->listen_host : "*", rs->listen_port,
           rs->connect_host, rs->connect_port);
    log_unlock();

    while (!rs->stop) {
        fd_set rfds;
        struct timeval tv;
        socket_t plain_sock, connected;
        struct channel ch;

        FD_ZERO(&rfds);
        FD_SET(listener, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select((int)listener + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
        if (rs->stop) break;

        plain_sock = accept(listener, NULL, NULL);
        if (plain_sock == INVALID_SOCKET) continue;

        connected = connect_tcp(rs->connect_host, rs->connect_port);
        if (connected == INVALID_SOCKET) {
            log_lock();
            fprintf(stderr, "[route %d] failed to connect to secure peer %s:%s\n",
                    rs->id, rs->connect_host, rs->connect_port);
            log_unlock();
            CLOSESOCK(plain_sock);
            continue;
        }

        memset(&ch, 0, sizeof(ch));
        ch.route_id = rs->id;
        ch.is_master = rs->is_master;
        ch.use_ml_kem = rs->use_ml_kem;
        ch.update_rekey_messages = rs->update_rekey_messages;
        ch.session_rekey_messages = rs->session_rekey_messages;
        memcpy(ch.send_nonce_prefix, "SAm0", 4);
        ch.secure_sock = connected;

        if (master_handshake(&ch, g_auth_cfg) < 0) {
            log_lock();
            fprintf(stderr, "[route %d] master handshake failed\n", rs->id);
            log_unlock();
        } else {
            log_lock();
            printf("[route %d] secure session established using %s; relaying traffic\n",
                   rs->id, rs->use_ml_kem ? "ML-KEM-512" : "X25519 ECDH");
            log_unlock();
            relay(plain_sock, &ch, &rs->stop);
        }

        CLOSESOCK(plain_sock);
        CLOSESOCK(connected);
        OPENSSL_cleanse(ch.session_key, sizeof(ch.session_key));
        OPENSSL_cleanse(ch.update_key, sizeof(ch.update_key));
        print_stats_report(&ch);
        free_stats(&ch);
        if (!rs->stop) {
            log_lock();
            printf("[route %d] session ended; waiting for next local SAv5 connection\n", rs->id);
            log_unlock();
        }
    }
    CLOSESOCK(listener);
    log_lock();
    printf("[route %d] route stopped\n", rs->id);
    log_unlock();
    return 0;
}

/*
 * Outstation-side route thread: binds this route's secure listen port once,
 * then serves incoming secure peer connections forever, each paired with a
 * fresh connection to this route's local plaintext SAv5 device. accept() is
 * polled the same way as master_route_thread, for the same reason.
 */
static THREAD_RET THREAD_CALL outstation_route_thread(void *arg)
{
    struct route_slot *rs = (struct route_slot *)arg;
    socket_t listener;

    listener = listen_tcp(rs->listen_host, rs->listen_port);
    if (listener == INVALID_SOCKET) {
        log_lock();
        fprintf(stderr, "[route %d] failed to listen on secure %s:%s\n",
                rs->id, rs->listen_host ? rs->listen_host : "*", rs->listen_port);
        log_unlock();
        return 0;
    }
    log_lock();
    printf("[route %d] outstation: waiting for secure proxy connections on %s:%s (-> local SAv5 %s:%s)\n",
           rs->id, rs->listen_host ? rs->listen_host : "*", rs->listen_port,
           rs->connect_host, rs->connect_port);
    log_unlock();

    if (rs->announce_admin_host && rs->announce_admin_port) {
        announce_route(rs->announce_admin_host, rs->announce_admin_port, rs->announce_host, rs->id, rs->listen_port);
    }

    while (!rs->stop) {
        fd_set rfds;
        struct timeval tv;
        socket_t accepted, plain_sock;
        struct channel ch;

        FD_ZERO(&rfds);
        FD_SET(listener, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select((int)listener + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
        if (rs->stop) break;

        accepted = accept(listener, NULL, NULL);
        if (accepted == INVALID_SOCKET) continue;

        memset(&ch, 0, sizeof(ch));
        ch.route_id = rs->id;
        ch.is_master = rs->is_master;
        ch.use_ml_kem = rs->use_ml_kem;
        ch.update_rekey_messages = rs->update_rekey_messages;
        ch.session_rekey_messages = rs->session_rekey_messages;
        memcpy(ch.send_nonce_prefix, "SAo0", 4);
        ch.secure_sock = accepted;

        if (outstation_handshake(&ch, g_auth_cfg) < 0) {
            log_lock();
            fprintf(stderr, "[route %d] outstation handshake failed\n", rs->id);
            log_unlock();
            CLOSESOCK(accepted);
            OPENSSL_cleanse(ch.session_key, sizeof(ch.session_key));
            OPENSSL_cleanse(ch.update_key, sizeof(ch.update_key));
            free_stats(&ch);
            continue;
        }

        plain_sock = connect_tcp(rs->connect_host, rs->connect_port);
        if (plain_sock == INVALID_SOCKET) {
            log_lock();
            fprintf(stderr, "[route %d] failed to connect to local SAv5 endpoint %s:%s\n",
                    rs->id, rs->connect_host, rs->connect_port);
            log_unlock();
        } else {
            log_lock();
            printf("[route %d] secure session established using %s; relaying traffic\n",
                   rs->id, rs->use_ml_kem ? "ML-KEM-512" : "X25519 ECDH");
            log_unlock();
            relay(plain_sock, &ch, &rs->stop);
            CLOSESOCK(plain_sock);
        }

        CLOSESOCK(accepted);
        OPENSSL_cleanse(ch.session_key, sizeof(ch.session_key));
        OPENSSL_cleanse(ch.update_key, sizeof(ch.update_key));
        print_stats_report(&ch);
        free_stats(&ch);
        if (!rs->stop) {
            log_lock();
            printf("[route %d] session ended; waiting for next secure proxy connection\n", rs->id);
            log_unlock();
        }
    }
    CLOSESOCK(listener);
    log_lock();
    printf("[route %d] route stopped\n", rs->id);
    log_unlock();
    return 0;
}

/*
 * Adds a route from an admin "ADD LISTEN_PORT:CONNECT_HOST:CONNECT_PORT"
 * command: parses spec (mutating it in place, same as add_route_from_spec),
 * builds a route_slot inheriting this process's mode/crypto/rekey settings,
 * registers it, and starts its thread. Writes a response line into resp.
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

    rs = route_slot_new(cfg->listen_host, spec, first_colon + 1, last_colon + 1,
                         cfg->is_master, cfg->use_ml_kem,
                         cfg->update_rekey_messages, cfg->session_rekey_messages,
                         cfg->announce_host, cfg->announce_admin_host, cfg->announce_admin_port);
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

/*
 * Removes a route by id: pulls it out of the registry immediately (so LIST
 * stops showing it right away), asks its thread to stop, and waits for it to
 * exit. The thread notices rs->stop within about a second (its accept/relay
 * polling interval), so this call typically returns within a second or two.
 */
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

/* Reads one newline-terminated line (stripping \r) from a socket, byte at a time; fine for admin traffic. */
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
 * command per connection. Lets an operator add or remove outstations (or
 * local devices, on the outstation side) from a running process without
 * restarting it: ADD LISTEN_PORT:CONNECT_HOST:CONNECT_PORT, REMOVE ID, LIST.
 * Bound to --control-host (default 127.0.0.1) so it is not exposed to the
 * network unless explicitly asked to be; the protocol has no authentication.
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

/*
 * One-shot admin client: connects to a running instance's control channel,
 * sends the single ADD/REMOVE/LIST command given on this invocation's command
 * line, prints whatever the server sends back, and exits. Lets an operator
 * add/remove routes with the same binary instead of needing a raw TCP client.
 */
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

/*
 * Entry point for the SAv6 proxy. Sets up socket state, loads OpenSSL providers,
 * seeds the live route registry from the command line's initial route(s), and
 * (if --control-port is set) starts the admin control channel so routes can be
 * added/removed at runtime without restarting the process; otherwise behaves
 * like before and simply blocks on the initial routes' threads, which
 * themselves run forever. A single process can serve many outstations this
 * way (point-to-multipoint), and --admin/--add/--remove/--list turn this same
 * binary into a client for managing an already-running instance.
 */
int main(int argc, char **argv)
{
    struct config cfg;
    OSSL_PROVIDER *provider = NULL;
    int i;

#ifdef _WIN32
    /* MinGW/UCRT's CRT treats _IOLBF the same as full buffering for
     * redirected streams, so line-buffering alone won't flush here. */
    setvbuf(stdout, NULL, _IONBF, 0);
#else
    setvbuf(stdout, NULL, _IOLBF, 0);
#endif

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
    g_auth_cfg = &cfg;
    /* Load default provider for ML-KEM and other algorithms */
    provider = OSSL_PROVIDER_load(NULL, "default");
    if (!provider) {
        fprintf(stderr, "Failed to load default provider\n");
        return 1;
    }
    OpenSSL_add_all_algorithms();

    if (cfg.update_rekey_messages) {
        printf("automatic Update Key rekey after every %llu protected data frames observed by master relay\n",
               (unsigned long long)cfg.update_rekey_messages);
    }
    if (cfg.session_rekey_messages) {
        printf("automatic Session Key rekey after every %llu protected data frames observed by master relay\n",
               (unsigned long long)cfg.session_rekey_messages);
    }
    printf("starting %d route%s in %s mode\n", cfg.route_count, cfg.route_count == 1 ? "" : "s",
           cfg.is_master ? "master" : "outstation");

    for (i = 0; i < cfg.route_count; i++) {
        struct route_slot *rs = route_slot_new(cfg.routes[i].listen_host, cfg.routes[i].listen_port,
                                                cfg.routes[i].connect_host, cfg.routes[i].connect_port,
                                                cfg.is_master, cfg.use_ml_kem,
                                                cfg.update_rekey_messages, cfg.session_rekey_messages,
                                                cfg.announce_host, cfg.announce_admin_host, cfg.announce_admin_port);
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
        /* No admin control requested: block on the initially configured
         * routes' threads, which themselves also loop forever, same as before. */
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
    OSSL_PROVIDER_unload(provider);
    socket_done();
    return 0;
}
