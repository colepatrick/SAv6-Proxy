#include <errno.h>
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

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#define MAGIC "SAV6PXY1"
#define MAGIC_LEN 8
#define VERSION 1
#define ALG_ECDH_X25519 1
#define ALG_MLKEM768 2

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

struct config {
    int is_master;
    int use_ml_kem;
    const char *listen_host;
    const char *listen_port;
    const char *connect_host;
    const char *connect_port;
};

struct channel {
    socket_t secure_sock;
    unsigned char session_key[SESSION_KEY_LEN];
    unsigned char send_nonce_prefix[4];
    uint64_t send_counter;
    uint64_t recv_counter;
};

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --mode master [--listen-host HOST] --listen-port PLAIN_PORT --connect-host PROXY_HOST --connect-port PROXY_PORT [--ml-kem]\n"
        "  %s --mode outstation [--listen-host HOST] --listen-port PROXY_PORT --connect-host SAv5_HOST --connect-port SAv5_PORT [--ml-kem]\n\n"
        "Master mode listens for the local SAv5 program, then connects to the remote secure proxy.\n"
        "Outstation mode listens for the secure proxy, then connects to the local SAv5 program.\n"
        "If --listen-host is omitted, the proxy listens on all local interfaces.\n",
        prog, prog);
}

static void die_ssl(const char *what)
{
    fprintf(stderr, "%s failed\n", what);
    exit(1);
}

static void log_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;
    printf("%s (%zu bytes): ", label, len);
    for (i = 0; i < len; i++) printf("%02X", buf[i]);
    putchar('\n');
}

static void log_step(const char *label)
{
    printf("\n=== %s ===\n", label);
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

static int send_msg(socket_t s, uint8_t type, const void *payload, uint32_t len)
{
    if (send_all(s, &type, 1) < 0) return -1;
    if (send_u32(s, len) < 0) return -1;
    if (len && send_all(s, payload, len) < 0) return -1;
    return 0;
}

static int recv_msg(socket_t s, uint8_t *type, unsigned char **payload, uint32_t *len)
{
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
    return 0;
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

static int hkdf_sha256(const unsigned char *secret, size_t secret_len,
                       const char *info, unsigned char out[UPDATE_KEY_LEN])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    const unsigned char salt[] = "SAv6-proxy-update-key";
    int ok = 0;

    if (!ctx) return -1;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt) - 1) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, secret_len) <= 0) goto done;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char *)info, strlen(info)) <= 0) goto done;
    {
        size_t out_len = UPDATE_KEY_LEN;
        if (EVP_PKEY_derive(ctx, out, &out_len) <= 0 || out_len != UPDATE_KEY_LEN) goto done;
    }
    ok = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

static EVP_PKEY *make_x25519_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    return key;
}

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

static int derive_x25519(EVP_PKEY *priv, const unsigned char *peer_pub, size_t peer_pub_len,
                         unsigned char update_key[UPDATE_KEY_LEN])
{
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *secret = NULL;
    size_t secret_len = 0;
    int ok = 0;

    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, peer_pub_len);
    if (!peer) goto done;
    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) goto done;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto done;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) goto done;
    secret = (unsigned char *)malloc(secret_len);
    if (!secret) goto done;
    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) goto done;
    log_hex("ECDH raw shared secret", secret, secret_len);
    if (hkdf_sha256(secret, secret_len, "ECDH-X25519", update_key) < 0) goto done;
    log_hex("ECDH HKDF-derived Update Key", update_key, UPDATE_KEY_LEN);
    ok = 1;
done:
    if (secret) OPENSSL_cleanse(secret, secret_len);
    free(secret);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return ok ? 0 : -1;
}

static int aes_wrap_key(const unsigned char update_key[UPDATE_KEY_LEN],
                        const unsigned char session_key[SESSION_KEY_LEN],
                        unsigned char **wrapped, int *wrapped_len)
{
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
    return 0;
fail:
    EVP_CIPHER_CTX_free(ctx);
    free(*wrapped);
    *wrapped = NULL;
    return -1;
}

static int aes_unwrap_key(const unsigned char update_key[UPDATE_KEY_LEN],
                          const unsigned char *wrapped, int wrapped_len,
                          unsigned char session_key[SESSION_KEY_LEN])
{
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
    return ok ? 0 : -1;
}

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

static int send_encrypted(struct channel *ch, const unsigned char *plain, uint32_t plain_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char nonce[GCM_NONCE_LEN], tag[GCM_TAG_LEN];
    unsigned char *buf = NULL;
    int len = 0, total = 0;
    uint32_t payload_len;
    int ok = -1;

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
    log_step("Encrypted outbound communication");
    printf("Plaintext bytes: %u\n", plain_len);
    log_hex("Plaintext", plain, plain_len);
    log_hex("AES-256-GCM nonce", nonce, GCM_NONCE_LEN);
    log_hex("AES-256-GCM ciphertext", buf + GCM_NONCE_LEN, (size_t)total);
    log_hex("AES-256-GCM tag", tag, GCM_TAG_LEN);
    printf("Sending encrypted frame payload bytes: %u\n", payload_len);
    ok = send_msg(ch->secure_sock, MSG_DATA, buf, payload_len);
done:
    free(buf);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int recv_encrypted(struct channel *ch, unsigned char **plain, uint32_t *plain_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *payload = NULL;
    uint8_t type;
    uint32_t payload_len;
    int len = 0, total = 0;
    int ok = -1;

    if (recv_msg(ch->secure_sock, &type, &payload, &payload_len) < 0) return -1;
    if (type == MSG_CLOSE) {
        printf("\nReceived encrypted close notification\n");
        free(payload);
        *plain = NULL;
        *plain_len = 0;
        return 1;
    }
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
    log_step("Decrypted inbound communication");
    printf("Encrypted frame payload bytes: %u\n", payload_len);
    log_hex("AES-256-GCM nonce", payload, GCM_NONCE_LEN);
    log_hex("AES-256-GCM ciphertext", payload + GCM_NONCE_LEN, *plain_len);
    log_hex("AES-256-GCM tag", payload + GCM_NONCE_LEN + *plain_len, GCM_TAG_LEN);
    log_hex("Decrypted plaintext", *plain, *plain_len);
    ch->recv_counter++;
    ok = 0;
done:
    if (ok < 0) {
        free(*plain);
        *plain = NULL;
        *plain_len = 0;
    }
    free(payload);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

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

static int send_client_hello(socket_t s, uint8_t alg, const unsigned char *body, uint32_t body_len)
{
    return send_hello(s, MSG_CLIENT_HELLO, alg, body, body_len);
}

static int send_server_hello(socket_t s, uint8_t alg, const unsigned char *body, uint32_t body_len)
{
    return send_hello(s, MSG_SERVER_HELLO, alg, body, body_len);
}

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
    log_hex("Received outstation X25519 public key", body, body_len);
    ok = derive_x25519(key, body, body_len, update_key);
done:
    free(payload);
    if (priv) OPENSSL_cleanse(priv, priv_len);
    free(priv);
    free(pub);
    EVP_PKEY_free(key);
    return ok;
}

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
    log_hex("Outstation X25519 private key", priv, priv_len);
    log_hex("Outstation X25519 public key", pub, pub_len);
    printf("Sending SERVER_HELLO with X25519 public key\n");
    if (send_server_hello(s, ALG_ECDH_X25519, pub, (uint32_t)pub_len) < 0) goto done;
    ok = derive_x25519(key, client_pub, client_pub_len, update_key);
done:
    if (priv) OPENSSL_cleanse(priv, priv_len);
    free(priv);
    free(pub);
    EVP_PKEY_free(key);
    return ok;
}

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
    printf("Sending CLIENT_HELLO requesting ML-KEM-768\n");
    if (send_client_hello(s, ALG_MLKEM768, NULL, 0) < 0) goto done;
    if (recv_msg(s, &type, &payload, &len) < 0) goto done;
    if (type != MSG_SERVER_HELLO || parse_hello(payload, len, &alg, &body, &body_len) < 0) goto done;
    if (alg != ALG_MLKEM768) goto done;
    log_hex("Received outstation ML-KEM-768 public key", body, body_len);

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (!pctx || EVP_PKEY_fromdata_init(pctx) <= 0) goto done;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
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
    log_hex("ML-KEM ciphertext sent to outstation", ciphertext, ciphertext_len);
    log_hex("ML-KEM shared secret", secret, secret_len);
    if (send_msg(s, MSG_CLIENT_HELLO, ciphertext, (uint32_t)ciphertext_len) < 0) goto done;
    if (hkdf_sha256(secret, secret_len, "ML-KEM-768", update_key) < 0) goto done;
    log_hex("ML-KEM HKDF-derived Update Key", update_key, UPDATE_KEY_LEN);
    ok = 0;
done:
    if (secret) OPENSSL_cleanse(secret, secret_len);
    free(secret);
    free(ciphertext);
    free(payload);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(peer);
    return ok;
}

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
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
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
    log_hex("Outstation ML-KEM-768 public key", public_key, public_key_len);
    printf("Sending SERVER_HELLO with ML-KEM-768 public key\n");
    if (send_server_hello(s, ALG_MLKEM768, public_key, (uint32_t)public_key_len) < 0) goto done;

    if (recv_msg(s, &type, &payload, &len) < 0) goto done;
    if (type != MSG_CLIENT_HELLO) goto done;
    log_hex("Received master ML-KEM ciphertext", payload, len);
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!pctx || EVP_PKEY_decapsulate_init(pctx, NULL) <= 0) goto done;
    if (EVP_PKEY_decapsulate(pctx, NULL, &secret_len, payload, len) <= 0) goto done;
    secret = (unsigned char *)malloc(secret_len);
    if (!secret) goto done;
    if (EVP_PKEY_decapsulate(pctx, secret, &secret_len, payload, len) <= 0) goto done;
    log_hex("ML-KEM shared secret", secret, secret_len);
    if (hkdf_sha256(secret, secret_len, "ML-KEM-768", update_key) < 0) goto done;
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

static int master_handshake(socket_t s, int use_ml_kem, unsigned char session_key[SESSION_KEY_LEN])
{
    unsigned char update_key[UPDATE_KEY_LEN];
    unsigned char *wrapped = NULL;
    int wrapped_len = 0;
    int ok = -1;

    if (use_ml_kem) {
        if (mlkem_master_handshake(s, update_key) < 0) goto done;
    } else {
        if (ecdh_master_handshake(s, update_key) < 0) goto done;
    }
    log_step("Master session key establishment");
    if (RAND_bytes(session_key, SESSION_KEY_LEN) != 1) goto done;
    log_hex("Generated AES-256-GCM session key", session_key, SESSION_KEY_LEN);
    if (aes_wrap_key(update_key, session_key, &wrapped, &wrapped_len) < 0) goto done;
    log_hex("AES Key Wrap output carrying session key", wrapped, (size_t)wrapped_len);
    printf("Sending WRAPPED_SESSION to outstation proxy\n");
    if (send_msg(s, MSG_WRAPPED_SESSION, wrapped, (uint32_t)wrapped_len) < 0) goto done;
    ok = 0;
done:
    OPENSSL_cleanse(update_key, sizeof(update_key));
    free(wrapped);
    return ok;
}

static int outstation_handshake(socket_t s, int use_ml_kem, unsigned char session_key[SESSION_KEY_LEN])
{
    unsigned char update_key[UPDATE_KEY_LEN];
    unsigned char *payload = NULL, *wrapped = NULL;
    uint8_t type, alg;
    uint32_t len, body_len, wrapped_len;
    const unsigned char *body;
    int ok = -1;

    if (recv_msg(s, &type, &payload, &len) < 0) goto done;
    if (type != MSG_CLIENT_HELLO || parse_hello(payload, len, &alg, &body, &body_len) < 0) goto done;
    if (use_ml_kem) {
        if (alg != ALG_MLKEM768 || body_len != 0) goto done;
        if (mlkem_outstation_handshake(s, update_key) < 0) goto done;
    } else {
        if (alg != ALG_ECDH_X25519) goto done;
        if (ecdh_outstation_handshake(s, body, body_len, update_key) < 0) goto done;
    }
    free(payload);
    payload = NULL;
    if (recv_msg(s, &type, &wrapped, &wrapped_len) < 0) goto done;
    if (type != MSG_WRAPPED_SESSION) goto done;
    log_step("Outstation session key establishment");
    log_hex("Received AES Key Wrap payload", wrapped, wrapped_len);
    if (aes_unwrap_key(update_key, wrapped, (int)wrapped_len, session_key) < 0) goto done;
    log_hex("Unwrapped AES-256-GCM session key", session_key, SESSION_KEY_LEN);
    ok = 0;
done:
    OPENSSL_cleanse(update_key, sizeof(update_key));
    free(payload);
    free(wrapped);
    return ok;
}

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
        } else if (strcmp(argv[i], "--help") == 0) {
            return -1;
        } else {
            return -1;
        }
    }
    return (mode_set && cfg->listen_port && cfg->connect_host && cfg->connect_port) ? 0 : -1;
}

int main(int argc, char **argv)
{
    struct config cfg;
    socket_t listener = INVALID_SOCKET;
    socket_t accepted = INVALID_SOCKET;
    socket_t connected = INVALID_SOCKET;
    socket_t plain_sock = INVALID_SOCKET;
    struct channel ch;
    int rc = 1;

    if (parse_args(argc, argv, &cfg) < 0) {
        usage(argv[0]);
        return 2;
    }
    if (socket_init() != 0) {
        fprintf(stderr, "socket initialization failed\n");
        return 1;
    }
    OpenSSL_add_all_algorithms();
    memset(&ch, 0, sizeof(ch));

    if (cfg.is_master) {
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
        if (master_handshake(ch.secure_sock, cfg.use_ml_kem, ch.session_key) < 0) die_ssl("master handshake");
    } else {
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

        if (outstation_handshake(ch.secure_sock, cfg.use_ml_kem, ch.session_key) < 0) die_ssl("outstation handshake");
        connected = connect_tcp(cfg.connect_host, cfg.connect_port);
        if (connected == INVALID_SOCKET) {
            fprintf(stderr, "failed to connect to local SAv5 endpoint %s:%s\n", cfg.connect_host, cfg.connect_port);
            goto done;
        }
        plain_sock = connected;
    }

    printf("secure session established using %s; relaying traffic\n", cfg.use_ml_kem ? "ML-KEM-768" : "X25519 ECDH");
    rc = relay(plain_sock, &ch) == 0 ? 0 : 1;

done:
    if (plain_sock != INVALID_SOCKET) CLOSESOCK(plain_sock);
    if (connected != INVALID_SOCKET && connected != plain_sock) CLOSESOCK(connected);
    if (accepted != INVALID_SOCKET && accepted != plain_sock && accepted != ch.secure_sock) CLOSESOCK(accepted);
    if (ch.secure_sock != INVALID_SOCKET && ch.secure_sock != connected && ch.secure_sock != accepted) CLOSESOCK(ch.secure_sock);
    if (listener != INVALID_SOCKET) CLOSESOCK(listener);
    OPENSSL_cleanse(ch.session_key, sizeof(ch.session_key));
    socket_done();
    return rc;
}
