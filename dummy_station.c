#include <ctype.h>
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
/*
 * Cross-platform millisecond sleep helper used by the dummy master between
 * test messages.
 */
static void sleep_ms(unsigned int ms) { Sleep(ms); }
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
/*
 * Cross-platform millisecond sleep helper used by the dummy master between
 * test messages.
 */
static void sleep_ms(unsigned int ms) { usleep(ms * 1000); }
#endif

#define BUF_SIZE 4096

struct config {
    int is_master;
    int mode_set;
    const char *listen_host;
    const char *listen_port;
    const char *connect_host;
    const char *connect_port;
    const char *message;
    int count;
    unsigned int interval_ms;
};

/*
 * Simple plaintext-only test harness for exercising the SAv6 proxy.
 * The dummy master sends test payloads and waits for plaintext acknowledgments.
 * The dummy outstation listens for plaintext and responds with a fixed ACK.
 */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --role master --connect-host HOST --connect-port PORT [--message TEXT] [--count N] [--interval-ms MS]\n"
        "  %s --role outstation [--listen-host HOST] --listen-port PORT\n\n"
        "This is a plaintext-only placeholder station for exercising the SAv6 proxy.\n"
        "Master connects and sends plaintext test messages.\n"
        "Outstation listens, prints plaintext bytes, and replies with plaintext ACKs.\n",
        prog, prog);
}

/*
 * Initialize sockets on Windows and do nothing on Unix-like systems.
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
 * Send an entire buffer over TCP, retrying until all bytes are transmitted.
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
 * Create a TCP connection to the specified host and port.
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
 * Create a listening TCP socket on the specified host and port.
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
 * Print received plaintext in a readable way, escaping non-printable bytes.
 */
static void print_plaintext(const unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (buf[i] == '\n') {
            putchar('\n');
        } else if (buf[i] == '\r') {
            fputs("\\r", stdout);
        } else if (isprint(buf[i]) || buf[i] == '\t') {
            putchar(buf[i]);
        } else {
            printf("\\x%02X", buf[i]);
        }
    }
    if (len == 0 || buf[len - 1] != '\n') putchar('\n');
}

/*
 * Wait for a plaintext response from the peer with a timeout.
 */
static int wait_for_response(socket_t s, unsigned int timeout_ms)
{
    fd_set rfds;
    struct timeval tv;
    unsigned char buf[BUF_SIZE];
    int n;

    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    tv.tv_sec = (long)(timeout_ms / 1000);
    tv.tv_usec = (long)((timeout_ms % 1000) * 1000);
    n = select((int)s + 1, &rfds, NULL, NULL, &tv);
    if (n <= 0) return n;
    n = recv(s, (char *)buf, sizeof(buf), 0);
    if (n <= 0) return -1;
    printf("received plaintext response: ");
    print_plaintext(buf, n);
    return 1;
}

/*
 * Dummy master: connect to the proxy and send plaintext test messages.
 */
static int run_master(const struct config *cfg)
{
    socket_t s;
    int i;

    s = connect_tcp(cfg->connect_host, cfg->connect_port);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "failed to connect to %s:%s\n", cfg->connect_host, cfg->connect_port);
        return 1;
    }

    printf("plaintext master connected to %s:%s\n", cfg->connect_host, cfg->connect_port);
    for (i = 1; i <= cfg->count; i++) {
        char line[BUF_SIZE];
        int len = snprintf(line, sizeof(line), "%s seq=%d\n", cfg->message, i);
        if (len < 0 || len >= (int)sizeof(line)) {
            fprintf(stderr, "message too long\n");
            CLOSESOCK(s);
            return 1;
        }
        printf("sending plaintext: %s", line);
        if (send_all(s, line, (size_t)len) < 0) {
            fprintf(stderr, "send failed\n");
            CLOSESOCK(s);
            return 1;
        }
        if (wait_for_response(s, 2000) < 0) {
            fprintf(stderr, "connection closed while waiting for response\n");
            CLOSESOCK(s);
            return 1;
        }
        if (i < cfg->count) sleep_ms(cfg->interval_ms);
    }

    CLOSESOCK(s);
    return 0;
}

/*
 * Dummy outstation: listen for a proxy connection and echo back plaintext ACKs.
 */
static int run_outstation(const struct config *cfg)
{
    socket_t listener, client;
    unsigned char buf[BUF_SIZE];
    int seq = 1;
    int seeded = 0;

    listener = listen_tcp(cfg->listen_host, cfg->listen_port);
    if (listener == INVALID_SOCKET) {
        fprintf(stderr, "failed to listen on %s:%s\n",
                cfg->listen_host ? cfg->listen_host : "*", cfg->listen_port);
        return 1;
    }

    printf("plaintext outstation listening on %s:%s\n",
           cfg->listen_host ? cfg->listen_host : "*", cfg->listen_port);
    client = accept(listener, NULL, NULL);
    CLOSESOCK(listener);
    if (client == INVALID_SOCKET) {
        fprintf(stderr, "accept failed\n");
        return 1;
    }
    printf("plaintext outstation accepted connection\n");

    for (;;) {
        int n = recv(client, (char *)buf, sizeof(buf), 0);
        char ack[300];
        int ack_len;

        if (n <= 0) break;
        printf("received plaintext request: ");
        print_plaintext(buf, n);
        ack_len = snprintf(ack, sizeof(ack), "DNP3_PLACEHOLDER_ACK seq=%d bytes=%d\n", seq++, n);
        if (ack_len < 0 || ack_len >= (int)sizeof(ack)) break;

        /* Seed random number generator once */
        if (!seeded) {
            srand((unsigned int)time(NULL));
            seeded = 1;
        }

        /* Generate random target size between current ack_len and 300 bytes */
        int target_len = ack_len + (rand() % (301 - ack_len));
        if (target_len > 300) target_len = 300;
        if (target_len < ack_len) target_len = ack_len;

        /* Pad with random bytes if needed */
        if (target_len > ack_len) {
            int pad_len = target_len - ack_len;
            for (int i = 0; i < pad_len; i++) {
                ack[ack_len + i] = (char)(rand() % 256);
            }
            ack_len = target_len;
        }

        if (send_all(client, ack, (size_t)ack_len) < 0) break;
        printf("sent plaintext response (%d bytes)\n", ack_len);
    }

    CLOSESOCK(client);
    printf("plaintext outstation connection closed\n");
    return 0;
}

/*
 * Parse a positive integer argument from the command line.
 */
static int parse_int(const char *s, int *out)
{    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!s[0] || *end || v <= 0 || v > 1000000L) return -1;
    *out = (int)v;
    return 0;
}

/*
 * Parse a positive unsigned integer argument from the command line.
 */
static int parse_uint(const char *s, unsigned int *out)
{    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (!s[0] || *end || v > 3600000UL) return -1;
    *out = (unsigned int)v;
    return 0;
}

/*
 * Parse command-line arguments for the dummy master/outstation.
 * The master role requires a target host/port, while outstation only needs a
 * listening port. Message, count, and interval are optional test parameters.
 */
static int parse_args(int argc, char **argv, struct config *cfg)
{
    int i;
    memset(cfg, 0, sizeof(*cfg));
    cfg->message = "DNP3_PLACEHOLDER_READ";
    cfg->count = 5;
    cfg->interval_ms = 1000;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "master") == 0) cfg->is_master = 1;
            else if (strcmp(argv[i], "outstation") == 0) cfg->is_master = 0;
            else return -1;
            cfg->mode_set = 1;
        } else if (strcmp(argv[i], "--listen-host") == 0 && i + 1 < argc) {
            cfg->listen_host = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            cfg->listen_port = argv[++i];
        } else if (strcmp(argv[i], "--connect-host") == 0 && i + 1 < argc) {
            cfg->connect_host = argv[++i];
        } else if (strcmp(argv[i], "--connect-port") == 0 && i + 1 < argc) {
            cfg->connect_port = argv[++i];
        } else if (strcmp(argv[i], "--message") == 0 && i + 1 < argc) {
            cfg->message = argv[++i];
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            if (parse_int(argv[++i], &cfg->count) < 0) return -1;
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            if (parse_uint(argv[++i], &cfg->interval_ms) < 0) return -1;
        } else if (strcmp(argv[i], "--help") == 0) {
            return -1;
        } else {
            return -1;
        }
    }

    if (!cfg->mode_set) return -1;
    if (cfg->is_master) return cfg->connect_host && cfg->connect_port ? 0 : -1;
    return cfg->listen_port ? 0 : -1;
}

/*
 * Entry point for the dummy station. It initializes sockets, parses the CLI,
 * and dispatches either the master or outstation behavior.
 */
int main(int argc, char **argv)
{
    struct config cfg;
    int rc;

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

    rc = cfg.is_master ? run_master(&cfg) : run_outstation(&cfg);
    socket_done();
    return rc;
}
