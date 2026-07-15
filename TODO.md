# TODO - SAv6 TLS debug instrumentation

- [ ] Inspect current `SAv6_proxy_tls.c` structure to identify where to add logging and counters.
- [ ] Add CLI flags to control verbosity/key dumping (default off where appropriate).
- [ ] Implement TLS/session/certificate detail printing after handshake.
- [ ] Instrument relay loop to print:
  - sizes read from plaintext socket
  - sizes written via `SSL_write`
  - sizes read via `SSL_read`
  - sizes sent via `send`
  - errors via `SSL_get_error`
- [ ] Add running byte counters and final summary output.
- [ ] Rebuild with `make proxy-tls`.
- [ ] Run the documented local TLS test flow with `dummy_station` and verify logs.

