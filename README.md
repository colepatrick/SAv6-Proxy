# SAv6 Proxy and Dummy DNP3 Station

This directory contains two small C programs:

- `SAv6_proxy.c`: a TCP proxy that accepts plaintext DNP3-SAv5 bytes on one side, protects the proxy-to-proxy connection with SAv6-style key establishment and AES-256-GCM, then forwards plaintext bytes to the remote endpoint.
- `dummy_station.c`: a plaintext-only dummy DNP3-like station used for testing the proxy path. It does not implement real DNP3; it only sends and receives readable test messages over TCP.

The proxy treats DNP3 traffic as a byte stream. It does not parse DNP3 application data. Whatever plaintext bytes enter one proxy are encrypted, authenticated, sent to the other proxy, decrypted, and forwarded.

## Build

Build both programs:

```sh
make
```

Build only the proxy:

```sh
make proxy
```

Build only the dummy station:

```sh
make station
```

Show Makefile targets:

```sh
make help
```

### Windows OpenSSL

On Windows, the Makefile defaults to:

```make
OPENSSL_ROOT = C:/Program Files/OpenSSL-Win64
```

If OpenSSL is installed somewhere else, override the paths:

```sh
make OPENSSL_CPPFLAGS="-IC:/path/to/OpenSSL/include" OPENSSL_LDFLAGS="-LC:/path/to/OpenSSL/lib/VC/x64/MD"
```

### Linux or Other Unix-Like Systems

On Linux/macOS, the Makefile tries:

```sh
pkg-config --cflags openssl
pkg-config --libs openssl
```

If OpenSSL is in a custom location, override the values:

```sh
make OPENSSL_CPPFLAGS="-I/opt/openssl/include" \
     OPENSSL_LDFLAGS="-L/opt/openssl/lib" \
     OPENSSL_LDLIBS="-lssl -lcrypto"
```

ML-KEM mode requires OpenSSL 3.5 or newer with ML-KEM support. X25519 ECDH mode can work with older OpenSSL 3.x installations.

## Programs

### Point-to-multipoint (multiple outstations behind one master)

Both `SAv6_proxy` and `TLS_proxy` normally run as one point-to-point pair: one
listen port, one connect target, one session, and the process exits when that
session ends. Both now also support **routes**: repeat `--route
LISTEN_PORT:CONNECT_HOST:CONNECT_PORT` instead of the single
`--listen-port`/`--connect-host`/`--connect-port` flags (the two forms cannot
be mixed) to run several independent listen+connect pairings from one
process, each on its own thread with its own session keys. A route's
listener also keeps serving new connections after a session ends, instead of
exiting.

This is what lets one DNP3 master reach several outstations: run one
master-side process with one `--route` per outstation (each pointing at that
outstation's own outstation-side proxy), and run one outstation-side process
per physical device as before (or, symmetrically, give an outstation-side
process multiple routes to front several local devices from one process).
`--listen-host` applies to every route in the process.

```sh
# master-side: one process serving three outstations
./SAv6_proxy --mode master --listen-host 0.0.0.0 --route 19991:outstation1-proxy-host:20000 --route 19992:outstation2-proxy-host:20000 --route 19993:outstation3-proxy-host:20000

# each outstation still runs its own single-route (or multi-route) process, e.g.
./SAv6_proxy --mode outstation --listen-host 0.0.0.0 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001
```

`--ml-kem`/`--ml-kem-512` and the rekey-threshold flags apply to every route
in the process. Console output is prefixed with `[route N]` at the coarse
milestones (listen, accept, handshake, session end); low-level per-frame hex
dumps inside a route are not additionally tagged, so under concurrent load
they can interleave between routes on stdout — a cosmetic limitation of the
existing verbose logging, not a correctness issue.

#### Adding/removing outstations without restarting

By default the routes given on the command line are fixed for the life of
the process — adding an outstation means stopping and relaunching the
master-side process with one more `--route`, which briefly interrupts every
route (they're threads in one process), not just the new one.

To avoid that, start the process with an admin control channel and manage
routes from a separate, short-lived invocation of the same binary:

```sh
# server: same as before, plus --control-port (defaults --control-host to 127.0.0.1)
./SAv6_proxy --mode master --listen-host 0.0.0.0 --control-port 9000 \
  --route 19991:outstation1-proxy-host:20000 \
  --route 19992:outstation2-proxy-host:20000

# from another shell (or another host, if --control-host is opened up):
./SAv6_proxy --admin 127.0.0.1:9000 --list
./SAv6_proxy --admin 127.0.0.1:9000 --add 19993:outstation3-proxy-host:20000
./SAv6_proxy --admin 127.0.0.1:9000 --remove 2
```

A route added this way inherits the running process's mode/`--ml-kem`/rekey
settings (or, for `TLS_proxy`, its cert/key/CA/TLS settings) — only the new
route's own listen/connect endpoints are given. `REMOVE` stops that route's
listener and any in-progress session and waits for its thread to exit
(typically within about a second, since routes poll for a stop request
rather than blocking forever) without touching any other route. The control
channel has no authentication, which is why it binds to loopback by default;
only widen `--control-host` on a network you trust.

#### Self-registration: a new outstation adding itself to a master

An outstation never announces itself by default — it's a passive listener
with no notion of "the master" — so normally *you* (or something acting on
your behalf) has to run the `--add`/`--route` steps above. `--announce-to`
makes an outstation-side process do that for itself, natively, no separate
tooling required:

```sh
# master: as before, with its admin channel enabled
./SAv6_proxy --mode master --listen-host 0.0.0.0 --control-port 9000 \
  --route 19991:outstation1-proxy-host:20000

# outstation: same as always, plus --announce-to pointing at that admin channel
./SAv6_proxy --mode outstation --listen-host 0.0.0.0 --listen-port 20000 \
  --connect-host 127.0.0.1 --connect-port 20001 \
  --announce-to master-host:9000 [--announce-host this-outstation-reachable-host]
```

As soon as each of the outstation's routes finishes binding its listener, it
sends the master's admin channel the exact same `ADD` command `--admin
...--add` would (retried a few times, 2s apart, in case the master isn't up
yet), using its own listen port as the master-side port it's requesting and
its detected outbound IP as the advertised connect host, unless
`--announce-host` overrides one or both. This applies to every route the
process ever serves, including ones added later via the admin channel, not
just the ones given at startup — and it works the same way for both
`SAv6_proxy` and `TLS_proxy`. Outstation-only: combining `--announce-to` with
`--mode master` is a startup error. For this to reach across hosts, the
master's `--control-host` has to be widened beyond loopback, same tradeoff as
using the admin channel remotely for any other reason.

#### Optional web UI for the admin channel

`admin_ui.py` is a small, dependency-free (Python 3 stdlib only) browser UI
for the same ADD/REMOVE/LIST protocol — useful for testing, configuring, and
demos, without replacing the CLI in any way (both talk to the exact same
control channel and can be used interchangeably, even against the same
running proxy at the same time). It does not start or stop proxy processes;
point it at an already-running instance's `--control-port`.

```sh
python3 admin_ui.py --instance "master=127.0.0.1:9000" [--instance "other=127.0.0.1:9001" ...] \
  [--listen 0.0.0.0:8765]
```

Then open `http://<host-running-admin_ui.py>:8765/` in a browser: it shows a
live (polled every few seconds) table of routes for the selected instance,
with an Add-route form and a Remove button per row. `--instance` is
repeatable, so one page can manage several proxy processes (e.g. a master and
an outstation, or several masters) via a dropdown.

Run `admin_ui.py` on the **same host** as the proxy it manages (so it can
reach `--control-port` over loopback, keeping that protocol's total lack of
auth contained to localhost) and only widen `--listen` beyond `127.0.0.1` on
a network you trust, since the web UI itself has no authentication either.

#### Optional web UI for launching processes with any flags

`launch_ui.py` is a second, separate, dependency-free (stdlib only) local
web UI — it doesn't manage routes on an already-running proxy, it *starts*
`SAv6_proxy`/`TLS_proxy`/`dummy_station` for you, exposing every flag those
programs take as a form. It's meant to run on each host/container right
after you `git clone` and `make` there: open the page, fill in flags, click
Start, and it launches the binary as a local subprocess (same as typing the
command yourself), tracks it, and lets you tail its log or stop it.

```sh
python3 launch_ui.py [--bin-dir .] [--listen 0.0.0.0:8766]
```

When you start an outstation through this UI, it shows you the exact command
to add it to a master by hand; if you'd rather it be automatic, fill in the
master's admin channel (`host:port`) and the new route's listen port, and
right after starting the outstation this UI sends the master an `ADD`
command itself over the same protocol `admin_ui.py`/`--admin` use. This does
the same thing `--announce-to` (below) does natively in the C proxies now —
the UI's version predates that flag and is kept as a convenience for when
you're launching from the form anyway, but for anything started by hand or
scripted outside this UI, prefer `--announce-to` directly. Either way, for
cross-host registration to work the master's `--control-host` has to be
widened beyond the loopback default (e.g. `--control-host 0.0.0.0`), which is
a deliberate opt-in tradeoff since that channel has no authentication — keep
it on a network you trust, or leave `--control-host` at its default and use
the manual command instead.

Security note: this starts local processes with whatever flags are
requested, so network access to it is equivalent to shell access on that
host. It binds to loopback by default for the same reason `admin_ui.py`
does; only widen `--listen` on a network you trust.

### SAv6 Proxy

### TLS Proxy (TLS-protected tunnel)

The TLS variant replaces the SAV6-style secure proxy-to-proxy leg with standard TLS and relays raw plaintext bytes between stations.

Executable: `TLS_proxy(.exe)`

General usage:

```sh
# master-side: plaintext station -> TLS_proxy -> TLS -> outstation proxy
./TLS_proxy --mode master   [--listen-host HOST] --listen-port PLAIN_PORT --connect-host TLS_PROXY_HOST --connect-port TLS_PROXY_PORT [--insecure] [--timeout-ms MS] [--ml-kem]

# outstation-side: TLS server -> TLS_proxy -> plaintext station
./TLS_proxy --mode outstation [--listen-host HOST] --listen-port PROXY_PORT --connect-host SAv5_HOST --connect-port SAv5_PORT [--cert SERVER_CERT.pem --key SERVER_KEY.pem] [--insecure] [--timeout-ms MS] [--ml-kem]


```

Proxy-to-proxy security options:

- `--insecure`: skip certificate verification (default for easy local testing)
- `--ca PATH`: CA bundle to use when verification is enabled
- `--timeout-ms MS`: optional coarse timeout for the TLS handshake and relay loop
- `--ml-kem-512`: use ML-KEM-512 (post-quantum) key encapsulation mechanism for key exchange instead of classical ECDH. Requires OpenSSL 3.2+ with ML-KEM support.

### TLS local test flow (with dummy_station)

Example ports:

```text
19999 = master plaintext input (dummy master -> TLS master proxy)
20000 = TLS tunnel input (TLS outstation proxy listens)
20001 = outstation plaintext input (TLS outstation proxy -> dummy outstation)
```

1) Start plaintext outstation:

```sh
./dummy_station --role outstation --listen-host 127.0.0.1 --listen-port 20001
```

2) Start TLS outstation proxy (TLS server):

```sh
./TLS_proxy --mode outstation --listen-host 127.0.0.1 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001 --verbose --log-keys

```

3) Start TLS master proxy (TLS client):

```sh
./TLS_proxy --mode master --listen-host 127.0.0.1 --listen-port 19999 --connect-host 127.0.0.1 --connect-port 20000 --verbose --log-keys
```

4) Start plaintext dummy master:

```sh
./dummy_station --role master --connect-host 127.0.0.1 --connect-port 19999 --count 5
```

Stations themselves only see raw plaintext bytes; they do not need to know about TLS.


General usage:




```sh
./SAv6_proxy --mode master [--listen-host HOST] --listen-port PLAIN_PORT --connect-host PROXY_HOST --connect-port PROXY_PORT [--ml-kem] [--update-rekey-messages N] [--session-rekey-messages M]
./SAv6_proxy --mode outstation [--listen-host HOST] --listen-port PROXY_PORT --connect-host SAv5_HOST --connect-port SAv5_PORT [--ml-kem] [--update-rekey-messages N] [--session-rekey-messages M]
```

On Windows, use `SAv6_proxy.exe`.

Proxy options:

- `--mode master`: accepts a local plaintext master/SAv5 connection, then connects to the remote secure proxy.
- `--mode outstation`: accepts the secure proxy connection, then connects to the local plaintext outstation/SAv5 endpoint.
- `--listen-host HOST`: optional local interface to bind. Use `127.0.0.1` for local-only testing. Omit it to listen on all interfaces.
- `--listen-port PORT`: local port the proxy listens on.
- `--connect-host HOST`: host/IP the proxy connects to.
- `--connect-port PORT`: port the proxy connects to.
- `--ml-kem`: use OpenSSL ML-KEM-512 instead of X25519 ECDH to establish the Update Key.
- `--update-rekey-messages N`: establish a fresh Update Key after every `N` protected data frames observed by the master relay. `0` disables this.
- `--session-rekey-messages M`: establish a fresh Session Key after every `M` protected data frames observed by the master relay. `0` disables this.

The master proxy initiates runtime rekeying. The outstation proxy receives those control frames internally and does not forward them to the plaintext station.

### Dummy Station

General usage:

```sh
./dummy_station --role master --connect-host HOST --connect-port PORT [--message TEXT] [--count N] [--interval-ms MS]
./dummy_station --role outstation [--listen-host HOST] --listen-port PORT
```

On Windows, use `dummy_station.exe`.

Dummy station options:

- `--role master`: connect to a TCP endpoint and send plaintext test messages.
- `--role outstation`: listen for a TCP connection, print plaintext requests, and return plaintext ACKs.
- `--listen-host HOST`: optional local bind address for outstation mode.
- `--listen-port PORT`: local listen port for outstation mode.
- `--connect-host HOST`: remote host/IP for master mode.
- `--connect-port PORT`: remote port for master mode.
- `--message TEXT`: message prefix sent by the dummy master.
- `--count N`: number of messages to send.
- `--interval-ms MS`: delay between messages.

## Running Everything on One Computer

You can run both proxies and both dummy stations on the same machine. Use different localhost ports:

```text
dummy master
  -> master proxy plaintext listener
  -> encrypted localhost proxy tunnel
  -> outstation proxy secure listener
  -> dummy outstation
```

Example ports:

```text
19999 = master proxy plaintext input
20000 = outstation proxy secure input
20001 = dummy outstation plaintext input
```

Start the dummy outstation:

```sh
./dummy_station --role outstation --listen-host 127.0.0.1 --listen-port 20001
```

Start the outstation-side proxy:

```sh
./SAv6_proxy --mode outstation --listen-host 127.0.0.1 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001 --update-rekey-messages 10 --session-rekey-messages 3
```

Start the master-side proxy:

```sh
./SAv6_proxy --mode master --listen-host 127.0.0.1 --listen-port 19999 --connect-host 127.0.0.1 --connect-port 20000 --update-rekey-messages 10 --session-rekey-messages 3
```

Start the dummy master:

```sh
./dummy_station --role master --connect-host 127.0.0.1 --connect-port 19999 --count 15
```

On Windows, add `.exe` to the program names:

```powershell
.\dummy_station.exe --role outstation --listen-host 127.0.0.1 --listen-port 20001
.\SAv6_proxy.exe --mode outstation --listen-host 127.0.0.1 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001 --update-rekey-messages 10 --session-rekey-messages 3
.\SAv6_proxy.exe --mode master --listen-host 127.0.0.1 --listen-port 19999 --connect-host 127.0.0.1 --connect-port 20000 --update-rekey-messages 10 --session-rekey-messages 3
.\dummy_station.exe --role master --connect-host 127.0.0.1 --connect-port 19999 --count 5
```

## Testing ML-KEM

Add `--ml-kem` to both proxy commands:

```sh
./SAv6_proxy --mode outstation --listen-host 127.0.0.1 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001 --ml-kem
./SAv6_proxy --mode master --listen-host 127.0.0.1 --listen-port 19999 --connect-host 127.0.0.1 --connect-port 20000 --ml-kem
```

Both sides must agree. Do not run one proxy with `--ml-kem` and the other without it.

## Testing Rekeying

Add matching rekey settings to both proxy commands:

```sh
./SAv6_proxy --mode outstation --listen-host 127.0.0.1 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001 --update-rekey-messages 10 --session-rekey-messages 3
./SAv6_proxy --mode master --listen-host 127.0.0.1 --listen-port 19999 --connect-host 127.0.0.1 --connect-port 20000 --update-rekey-messages 10 --session-rekey-messages 3
```

Then send several dummy messages:

```sh
./dummy_station --role master --connect-host 127.0.0.1 --connect-port 19999 --count 15 --message DNP3_REKEY_TEST
```

The proxy terminal output will show new Update Key handshakes and new Session Key establishment events.

## Using Real SAv5/DNP3 Programs

Replace the dummy station programs with your real SAv5 software:

```text
Real SAv5 master
  -> master proxy --listen-port
  -> encrypted proxy tunnel
  -> outstation proxy
  -> real SAv5 outstation
```

For example, if the real outstation listens on `127.0.0.1:20001`, run the outstation proxy like this:

```sh
./SAv6_proxy --mode outstation --listen-host 0.0.0.0 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001
```

Then point the master proxy at the outstation proxy:

```sh
./SAv6_proxy --mode master --listen-host 127.0.0.1 --listen-port 19999 --connect-host OUTSTATION_PROXY_IP --connect-port 20000
```

Finally, configure the real SAv5 master to connect to:

```text
127.0.0.1:19999
```

## Encryption Pathway

The proxy uses this key path:

```text
X25519 ECDH or ML-KEM-512
  -> HKDF-SHA256
  -> 256-bit Update Key
  -> AES-256 Key Wrap
  -> 256-bit Session Key
  -> AES-256-GCM
  -> protected DNP3 byte stream
```

Default Update Key establishment uses X25519 ECDH:

```text
master public key <-> outstation public key
raw ECDH shared secret
HKDF-SHA256
Update Key
```

With `--ml-kem`, Update Key establishment uses OpenSSL ML-KEM-512:

```text
outstation ML-KEM public key
master ML-KEM ciphertext
shared secret
HKDF-SHA256
Update Key
```

The master proxy generates the Session Key randomly, wraps it with AES Key Wrap using the Update Key, and sends the wrapped key to the outstation proxy. Both proxies then use the Session Key for AES-256-GCM traffic.

Each encrypted data frame carries:

```text
12-byte GCM nonce
ciphertext
16-byte GCM tag
```

The nonce is:

```text
4-byte direction prefix + 8-byte counter
```

The direction prefixes are:

```text
SAm0 = master-to-outstation
SAo0 = outstation-to-master
```

## Debug Logging Warning

The proxy currently prints sensitive cryptographic values to the terminal, including private keys, raw shared secrets, Update Keys, Session Keys, AES-GCM nonces, ciphertext, tags, and plaintext.

That is useful for demonstration and lab verification, but it is not safe for production. Remove or disable these logs before using the proxy in any real environment.

## Common Problems

### Connection refused

Start programs in this order:

1. Dummy or real outstation endpoint.
2. Outstation-side proxy.
3. Master-side proxy.
4. Dummy or real master endpoint.

### ML-KEM compile errors

Install OpenSSL 3.5 or newer and ensure the Makefile is using those headers and libraries.
