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

#include <math.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/provider.h>

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
struct config {
    int is_master;
    int use_ml_kem;
    const char *listen_host;
    const char *listen_port;
    const char *connect_host;
    const char *connect_port;
    uint64_t update_rekey_messages;
    uint64_t session_rekey_messages;
};

struct channel {
    socket_t secure_sock;
    int is_master;
    int use_ml_kem;
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

    printf("\n\n========== Packet Statistics Report =========="
           "\n");

    if (ch->plaintext_count == 0 && ch->encrypted_count == 0) {
        printf("No packet data collected.\n");
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
        "Usage:\n"
        "  %s --mode master [--listen-host HOST] --listen-port PLAIN_PORT --connect-host PROXY_HOST --connect-port PROXY_PORT [--ml-kem] [--update-rekey-messages N] [--session-rekey-messages M]\n"
        "  %s --mode outstation [--listen-host HOST] --listen-port PROXY_PORT --connect-host SAv5_HOST --connect-port SAv5_PORT [--ml-kem] [--update-rekey-messages N] [--session-rekey-messages M]\n\n"
        "Master mode listens for the local SAv5 program, then connects to the remote secure proxy.\n"
        "Outstation mode listens for the secure proxy, then connects to the local SAv5 program.\n"
        "If --listen-host is omitted, the proxy listens on all local interfaces.\n"
        "Rekey intervals default to 0, which disables automatic rekeying.\n",
        prog, prog);
}

/*
 * Abort execution with a simple SSL-related error message.
 */
static void die_ssl(const char *what)
{
    fprintf(stderr, "%s failed\n", what);
    exit(1);
}

/*
 * Print a buffer in hex for debugging of keys, nonces, ciphertext, and tags.
 */
static void log_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;
    printf("%s (%zu bytes): ", label, len);
    for (i = 0; i < len; i++) printf("%02X", buf[i]);
    putchar('\n');
}

/*
 * Emit a labeled step marker in console output for tracing handshake and relay progress.
 */
static void log_step(const char *label)
{
    printf("\n=== %s ===\n", label);
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
        if (bind(s, rp->ai_addr, (int)rp->ai_addrlen) == 0 && listen(s, 1) == 0) break;
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

static int master_handshake(struct channel *ch)
{
    if (establish_master_update_key(ch) < 0) return -1;
    return establish_master_session_key(ch);
}

/*
 * Perform the outstation side of the initial secure handshake.
 * The outstation first handles the CLIENT_HELLO, establishes the update key,
 * then receives and unwraps the wrapped session key.
 */
static int outstation_handshake(struct channel *ch)
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
static int relay(socket_t plain_sock, struct channel *ch)
{
    fd_set rfds;
    unsigned char buf[MAX_FRAME];
    int done = 0;

    while (!done) {
        socket_t maxfd = plain_sock > ch->secure_sock ? plain_sock : ch->secure_sock;
        FD_ZERO(&rfds);
        FD_SET(plain_sock, &rfds);
        FD_SET(ch->secure_sock, &rfds);
        if (select((int)maxfd + 1, &rfds, NULL, NULL, NULL) <= 0) return -1;

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
 * Parse command-line arguments for proxy mode, host/port bindings, ML-KEM
 * selection, and optional rekey thresholds.
 */
static int parse_args(int argc, char **argv, struct config *cfg)
{
    int i;
    int mode_set = 0;
    memset(cfg, 0, sizeof(*cfg));
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "master") == 0) cfg->is_master = 1;
            else if (strcmp(argv[i], "outstation") == 0) cfg->is_master = 0;
            else return -1;
            mode_set = 1;
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            cfg->listen_port = argv[++i];
        } else if (strcmp(argv[i], "--listen-host") == 0 && i + 1 < argc) {
            cfg->listen_host = argv[++i];
        } else if (strcmp(argv[i], "--connect-host") == 0 && i + 1 < argc) {
            cfg->connect_host = argv[++i];
        } else if (strcmp(argv[i], "--connect-port") == 0 && i + 1 < argc) {
            cfg->connect_port = argv[++i];
        } else if (strcmp(argv[i], "--ml-kem") == 0) {
            cfg->use_ml_kem = 1;
        } else if (strcmp(argv[i], "--update-rekey-messages") == 0 && i + 1 < argc) {
            if (parse_u64_arg(argv[++i], &cfg->update_rekey_messages) < 0) return -1;
        } else if (strcmp(argv[i], "--session-rekey-messages") == 0 && i + 1 < argc) {
            if (parse_u64_arg(argv[++i], &cfg->session_rekey_messages) < 0) return -1;
        } else if (strcmp(argv[i], "--help") == 0) {
            return -1;
        } else {
            return -1;
        }
    }
    return (mode_set && cfg->listen_port && cfg->connect_host && cfg->connect_port) ? 0 : -1;
}

/*
 * Entry point for the SAv6 proxy. Sets up socket state, loads OpenSSL providers,
 * negotiates secure sessions, and begins relaying plaintext and encrypted traffic.
 */
int main(int argc, char **argv)
{
    struct config cfg;
    socket_t listener = INVALID_SOCKET;
    socket_t accepted = INVALID_SOCKET;
    socket_t connected = INVALID_SOCKET;
    socket_t plain_sock = INVALID_SOCKET;
    struct channel ch;
    OSSL_PROVIDER *provider = NULL;
    int rc = 1;

    if (parse_args(argc, argv, &cfg) < 0) {
        usage(argv[0]);
        return 2;
    }
    if (socket_init() != 0) {
        fprintf(stderr, "socket initialization failed\n");
        return 1;
    }
    /* Load default provider for ML-KEM and other algorithms */
    provider = OSSL_PROVIDER_load(NULL, "default");
    if (!provider) {
        fprintf(stderr, "Failed to load default provider\n");
        return 1;
    }
    OpenSSL_add_all_algorithms();
    memset(&ch, 0, sizeof(ch));
    ch.is_master = cfg.is_master;
    ch.use_ml_kem = cfg.use_ml_kem;
    ch.update_rekey_messages = cfg.update_rekey_messages;
    ch.session_rekey_messages = cfg.session_rekey_messages;
    if (ch.update_rekey_messages) {
        printf("automatic Update Key rekey after every %llu protected data frames observed by master relay\n",
               (unsigned long long)ch.update_rekey_messages);
    }
    if (ch.session_rekey_messages) {
        printf("automatic Session Key rekey after every %llu protected data frames observed by master relay\n",
               (unsigned long long)ch.session_rekey_messages);
    }

    if (cfg.is_master) {
        /*
         * Master mode: accept plaintext from the local SAv5 client, connect to
         * the remote secure peer, perform the secure handshake, then relay.
         */
        memcpy(ch.send_nonce_prefix, "SAm0", 4);
        listener = listen_tcp(cfg.listen_host, cfg.listen_port);
        if (listener == INVALID_SOCKET) {
            fprintf(stderr, "failed to listen on local/plain %s:%s\n",
                    cfg.listen_host ? cfg.listen_host : "*", cfg.listen_port);
            goto done;
        }
        printf("master: waiting for local SAv5 connection on %s:%s\n",
               cfg.listen_host ? cfg.listen_host : "*", cfg.listen_port);
        accepted = accept(listener, NULL, NULL);
        if (accepted == INVALID_SOCKET) goto done;
        plain_sock = accepted;

        connected = connect_tcp(cfg.connect_host, cfg.connect_port);
        if (connected == INVALID_SOCKET) {
            fprintf(stderr, "failed to connect to secure peer %s:%s\n", cfg.connect_host, cfg.connect_port);
            goto done;
        }
        ch.secure_sock = connected;
        if (master_handshake(&ch) < 0) die_ssl("master handshake");
    } else {
        /*
         * Outstation mode: accept the secure proxy connection and then connect
         * to the local plaintext SAv5 endpoint once the secure handshake is done.
         */
        memcpy(ch.send_nonce_prefix, "SAo0", 4);
        listener = listen_tcp(cfg.listen_host, cfg.listen_port);
        if (listener == INVALID_SOCKET) {
            fprintf(stderr, "failed to listen on secure %s:%s\n",
                    cfg.listen_host ? cfg.listen_host : "*", cfg.listen_port);
            goto done;
        }
        printf("outstation: waiting for secure proxy connection on %s:%s\n",
               cfg.listen_host ? cfg.listen_host : "*", cfg.listen_port);
        accepted = accept(listener, NULL, NULL);
        if (accepted == INVALID_SOCKET) goto done;
        ch.secure_sock = accepted;

        if (outstation_handshake(&ch) < 0) die_ssl("outstation handshake");
        connected = connect_tcp(cfg.connect_host, cfg.connect_port);
        if (connected == INVALID_SOCKET) {
            fprintf(stderr, "failed to connect to local SAv5 endpoint %s:%s\n", cfg.connect_host, cfg.connect_port);
            goto done;
        }
        plain_sock = connected;
    }

    printf("secure session established using %s; relaying traffic\n", cfg.use_ml_kem ? "ML-KEM-512" : "X25519 ECDH");
    rc = relay(plain_sock, &ch) == 0 ? 0 : 1;

done:
    if (plain_sock != INVALID_SOCKET) CLOSESOCK(plain_sock);
    if (connected != INVALID_SOCKET && connected != plain_sock) CLOSESOCK(connected);
    if (accepted != INVALID_SOCKET && accepted != plain_sock && accepted != ch.secure_sock) CLOSESOCK(accepted);
    if (ch.secure_sock != INVALID_SOCKET && ch.secure_sock != connected && ch.secure_sock != accepted) CLOSESOCK(ch.secure_sock);
    if (listener != INVALID_SOCKET) CLOSESOCK(listener);
    OPENSSL_cleanse(ch.session_key, sizeof(ch.session_key));
    OPENSSL_cleanse(ch.update_key, sizeof(ch.update_key));
    if (provider) OSSL_PROVIDER_unload(provider);
    socket_done();
    print_stats_report(&ch);
    free_stats(&ch);
    return rc;
}
