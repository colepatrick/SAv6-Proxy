#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define CLOSESOCK closesocket
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int socket_t;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSESOCK close
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#define BUF_SIZE 65536

struct config {
    int is_master;

    const char *listen_host;
    const char *listen_port;

    const char *connect_host;
    const char *connect_port;

    const char *cert_path;
    const char *key_path;
    const char *ca_path;

    int insecure;    /* if non-zero, skip peer/host verification */
    int verify_peer; /* if non-zero, verify peer cert (uses ca_path if provided) */

    int auto_cert; /* if non-zero, generate ephemeral server cert/key when --cert/--key missing (outstation mode) */

    int timeout_ms; /* for handshake and I/O select timeouts */

    int verbose;   /* print detailed connection/TLS information */
    int log_keys;  /* dump sensitive key/symmetric material (debug only) */
};

struct channel {
    socket_t plain_sock;
    socket_t tcp_secure_sock;

    SSL_CTX *ssl_ctx;
    SSL *ssl;

    int is_master;
};

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --mode master   [--listen-host HOST] --listen-port PLAIN_PORT --connect-host PROXY_HOST --connect-port PROXY_PORT [--ca PATH] [--cert PATH --key PATH] [--insecure] [--timeout-ms MS] [--verbose] [--log-keys]\n"
        "  %s --mode outstation [--listen-host HOST] --listen-port PROXY_PORT --connect-host SAv5_HOST --connect-port SAv5_PORT --cert PATH --key PATH [--ca PATH] [--insecure] [--timeout-ms MS] [--verbose] [--log-keys]\n\n"
        "This proxy replaces the SAV6 custom secure channel with standard TLS.\n"
        "Stations on each side see only raw plaintext bytes relayed through TLS.\n\n"
        "Common options:\n"
        "  --listen-host HOST   bind address (default: * / all interfaces)\n"
        "  --listen-port PORT   local listening port (plaintext input for master, TLS server input for outstation)\n"
        "  --connect-host HOST connect target host\n"
        "  --connect-port PORT connect target port\n"
        "  --insecure           do not verify peer certificate (default for convenience)\n"
        "  --ca PATH            CA bundle to use when verifying (only if verification enabled)\n"
        "  --timeout-ms MS      optional timeout used for TLS handshake and relay loop; default 0 (blocking)\n"
        "  --verbose            print detailed TLS/cert/session information and per-read/write sizes\n"
        "  --log-keys           ALSO dump sensitive key/symmetric material (includes TLS randoms; not safe for production)\n",
        prog, prog);
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
        if (bind(s, rp->ai_addr, (int)rp->ai_addrlen) == 0 && listen(s, 1) == 0) break;
        CLOSESOCK(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
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

static int parse_args(int argc, char **argv, struct config *cfg)
{
    int i;
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
            cfg->listen_port = argv[++i];
        } else if (strcmp(argv[i], "--connect-host") == 0 && i + 1 < argc) {
            cfg->connect_host = argv[++i];
        } else if (strcmp(argv[i], "--connect-port") == 0 && i + 1 < argc) {
            cfg->connect_port = argv[++i];
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
        } else if (strcmp(argv[i], "--help") == 0) {
            return -1;
        } else {
            return -1;
        }
    }

    /* required */
    if (!cfg->listen_port || !cfg->connect_host || !cfg->connect_port) return -1;

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
    return rc;
}

static int tls_configure_ctx_as_server(SSL_CTX *ctx, const struct config *cfg)
{
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

static int tls_handshake(SSL *ssl, struct config *cfg)
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
    if (cfg->is_master) rc = SSL_connect(ssl);
    else rc = SSL_accept(ssl);

    if (rc != 1) {
        print_ssl_error(cfg->is_master ? "SSL_connect" : "SSL_accept");
        return -1;
    }
    return 0;
}

static void log_bytes(const char *label, int n)
{
    if (n < 0) printf("%s: <error>\n", label);
    else printf("%s: %d bytes\n", label, n);
}

static int relay_loop(struct channel *ch, int timeout_ms, const struct config *cfg)
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
        }

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

            plain_to_tls_bytes += (uint64_t)n;

            int off = 0;
            while (off < n) {
                tls_sslwrite_calls++;
                int w = SSL_write(ch->ssl, plain_buf + off, (int)(n - off));
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
            int r = SSL_read(ch->ssl, tls_buf, sizeof(tls_buf));
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

int main(int argc, char **argv)
{
    struct config cfg;
    struct channel ch;
    socket_t listener = INVALID_SOCKET;
    socket_t accepted = INVALID_SOCKET;
    socket_t connected = INVALID_SOCKET;
    socket_t plain_sock = INVALID_SOCKET;

    if (parse_args(argc, argv, &cfg) < 0) {
        usage(argv[0]);
        return 2;
    }

    if (socket_init() != 0) {
        fprintf(stderr, "socket initialization failed\n");
        return 1;
    }

    openssl_init();

    memset(&ch, 0, sizeof(ch));
    ch.is_master = cfg.is_master;

    if (cfg.is_master) {
        listener = listen_tcp(cfg.listen_host, cfg.listen_port);
        if (listener == INVALID_SOCKET) {
            fprintf(stderr, "failed to listen on %s:%s\n",
                    cfg.listen_host ? cfg.listen_host : "*", cfg.listen_port);
            goto done;
        }
        printf("TLS-mesh master: waiting for plaintext station on %s:%s\n",
               cfg.listen_host ? cfg.listen_host : "*", cfg.listen_port);

        accepted = accept(listener, NULL, NULL);
        if (accepted == INVALID_SOCKET) {
            fprintf(stderr, "accept failed\n");
            goto done;
        }
        plain_sock = accepted;

        connected = connect_tcp(cfg.connect_host, cfg.connect_port);
        if (connected == INVALID_SOCKET) {
            fprintf(stderr, "failed to connect TLS server at %s:%s\n", cfg.connect_host, cfg.connect_port);
            goto done;
        }
        ch.tcp_secure_sock = connected;
        ch.plain_sock = plain_sock;

        const SSL_METHOD *method = TLS_client_method();
        ch.ssl_ctx = SSL_CTX_new(method);
        if (!ch.ssl_ctx) {
            print_ssl_error("SSL_CTX_new(client)");
            goto done;
        }
        if (tls_configure_ctx_as_client(ch.ssl_ctx, &cfg) < 0) {
            print_ssl_error("tls_configure_ctx_as_client");
            goto done;
        }

        ch.ssl = SSL_new(ch.ssl_ctx);
        if (!ch.ssl) {
            print_ssl_error("SSL_new");
            goto done;
        }

        SSL_set_fd(ch.ssl, (int)ch.tcp_secure_sock);
        printf("TLS-mesh master: performing TLS handshake to %s:%s\n", cfg.connect_host, cfg.connect_port);

        if (tls_handshake(ch.ssl, &cfg) < 0) goto done;

        printf("TLS-mesh master: TLS handshake complete; relaying plaintext bytes\n");
        print_tls_details(ch.ssl, &cfg);

        if (relay_loop(&ch, cfg.timeout_ms, &cfg) < 0) goto done;

    } else {
        listener = listen_tcp(cfg.listen_host, cfg.listen_port);
        if (listener == INVALID_SOCKET) {
            fprintf(stderr, "failed to listen on %s:%s\n",
                    cfg.listen_host ? cfg.listen_host : "*", cfg.listen_port);
            goto done;
        }
        printf("TLS-mesh outstation: waiting for TLS client on %s:%s\n",
               cfg.listen_host ? cfg.listen_host : "*", cfg.listen_port);

        accepted = accept(listener, NULL, NULL);
        if (accepted == INVALID_SOCKET) {
            fprintf(stderr, "accept failed\n");
            goto done;
        }
        ch.tcp_secure_sock = accepted;

        plain_sock = connect_tcp(cfg.connect_host, cfg.connect_port);
        if (plain_sock == INVALID_SOCKET) {
            fprintf(stderr, "failed to connect local plaintext station at %s:%s\n", cfg.connect_host, cfg.connect_port);
            goto done;
        }
        ch.plain_sock = plain_sock;

        const SSL_METHOD *method = TLS_server_method();
        ch.ssl_ctx = SSL_CTX_new(method);
        if (!ch.ssl_ctx) {
            print_ssl_error("SSL_CTX_new(server)");
            goto done;
        }
        if (tls_configure_ctx_as_server(ch.ssl_ctx, &cfg) < 0) {
            print_ssl_error("tls_configure_ctx_as_server");
            goto done;
        }

        ch.ssl = SSL_new(ch.ssl_ctx);
        if (!ch.ssl) {
            print_ssl_error("SSL_new");
            goto done;
        }

        SSL_set_fd(ch.ssl, (int)ch.tcp_secure_sock);
        printf("TLS-mesh outstation: performing TLS handshake\n");
        if (tls_handshake(ch.ssl, &cfg) < 0) goto done;

        printf("TLS-mesh outstation: TLS handshake complete; relaying plaintext bytes\n");
        print_tls_details(ch.ssl, &cfg);

        if (relay_loop(&ch, cfg.timeout_ms, &cfg) < 0) goto done;
    }

done:
    if (ch.ssl) {
        SSL_shutdown(ch.ssl);
    }
    if (ch.ssl) SSL_free(ch.ssl);
    if (ch.ssl_ctx) SSL_CTX_free(ch.ssl_ctx);

    if (plain_sock != INVALID_SOCKET) CLOSESOCK(plain_sock);
    if (connected != INVALID_SOCKET) CLOSESOCK(connected);
    if (accepted != INVALID_SOCKET && accepted != plain_sock && accepted != connected) CLOSESOCK(accepted);
    if (listener != INVALID_SOCKET) CLOSESOCK(listener);

    openssl_cleanup();
    socket_done();

    return 0;
}