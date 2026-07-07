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

### SAv6 Proxy

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
- `--ml-kem`: use OpenSSL ML-KEM-768 instead of X25519 ECDH to establish the Update Key.
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
./SAv6_proxy --mode outstation --listen-host 127.0.0.1 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001
```

Start the master-side proxy:

```sh
./SAv6_proxy --mode master --listen-host 127.0.0.1 --listen-port 19999 --connect-host 127.0.0.1 --connect-port 20000
```

Start the dummy master:

```sh
./dummy_station --role master --connect-host 127.0.0.1 --connect-port 19999 --count 5
```

On Windows, add `.exe` to the program names:

```powershell
.\dummy_station.exe --role outstation --listen-host 127.0.0.1 --listen-port 20001
.\SAv6_proxy.exe --mode outstation --listen-host 127.0.0.1 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001
.\SAv6_proxy.exe --mode master --listen-host 127.0.0.1 --listen-port 19999 --connect-host 127.0.0.1 --connect-port 20000
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
./SAv6_proxy --mode outstation --listen-host 127.0.0.1 --listen-port 20000 --connect-host 127.0.0.1 --connect-port 20001 --update-rekey-messages 2 --session-rekey-messages 3
./SAv6_proxy --mode master --listen-host 127.0.0.1 --listen-port 19999 --connect-host 127.0.0.1 --connect-port 20000 --update-rekey-messages 2 --session-rekey-messages 3
```

Then send several dummy messages:

```sh
./dummy_station --role master --connect-host 127.0.0.1 --connect-port 19999 --count 5 --message DNP3_REKEY_TEST
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
X25519 ECDH or ML-KEM-768
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

With `--ml-kem`, Update Key establishment uses OpenSSL ML-KEM-768:

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
