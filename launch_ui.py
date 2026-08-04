#!/usr/bin/env python3
"""
Minimal, dependency-free (Python 3 stdlib only) local process-launcher UI for
this repo's binaries: SAv6_proxy, TLS_proxy, dummy_station. Exposes every CLI
flag those programs take as a web form, launches the chosen binary as a local
subprocess with exactly the flags you picked, and lets you watch its log and
stop it.

This is a per-host tool: run it on whichever machine/container already has
the binaries built (after `make`), the same way you'd otherwise SSH in and
type the command by hand -- this script just types it for you and keeps
track of the resulting process. It does not deploy to other hosts, does not
create containers, and does not replace the CLI in any way.

When you start an outstation-side proxy, the master doesn't learn about it
automatically -- the outstation is a passive listener with no notion of "the
master". This UI can optionally do the registration step for you: if you
give it a running master's admin control channel (its --control-port, see
README.md), it will send that master an ADD command over the same protocol
`admin_ui.py`/`--admin` use, right after starting the outstation. If you
leave that blank, it shows you the exact command to run yourself instead.

Usage:
  python3 launch_ui.py [--bin-dir .] [--listen 127.0.0.1:8766]

Then open http://<this-host>:8766/ in a browser.

Security note: this literally starts local processes with attacker-chosen
flags on request -- treat network access to this UI as equivalent to shell
access on this host. It binds to loopback by default; only widen --listen on
a network you trust.
"""
import argparse
import json
import os
import shlex
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BIN_DIR = "."
LOG_DIR = "launch_ui_logs"

PROCS_LOCK = threading.Lock()
PROCS = {}       # id -> dict(binary, argv, popen, log_path, started_at)
NEXT_PROC_ID = 1


def exe_name(name):
    if os.name == "nt" and not name.endswith(".exe"):
        return name + ".exe"
    return name


def detect_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def send_admin_command(host, port, command, timeout=5.0):
    with socket.create_connection((host, int(port)), timeout=timeout) as s:
        s.sendall((command + "\n").encode("utf-8"))
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")


def build_argv(binary, f):
    """f is the parsed JSON form payload. Returns (argv_without_binary, errors)."""
    argv = []
    errors = []

    def flag(name, key):
        v = f.get(key)
        if v not in (None, ""):
            argv.extend([name, str(v)])

    def switch(name, key):
        if f.get(key):
            argv.append(name)

    if binary in ("SAv6_proxy", "TLS_proxy"):
        mode = f.get("mode")
        if mode not in ("master", "outstation"):
            errors.append("mode must be 'master' or 'outstation'")
        else:
            argv.extend(["--mode", mode])

        flag("--listen-host", "listen_host")

        routes = [r.strip() for r in (f.get("routes") or "").splitlines() if r.strip()]
        if routes:
            for r in routes:
                argv.extend(["--route", r])
        else:
            flag("--listen-port", "listen_port")
            flag("--connect-host", "connect_host")
            flag("--connect-port", "connect_port")

        switch("--ml-kem", "ml_kem")
        flag("--control-host", "control_host")
        flag("--control-port", "control_port")

        if binary == "SAv6_proxy":
            flag("--update-rekey-messages", "update_rekey_messages")
            flag("--session-rekey-messages", "session_rekey_messages")
        else:  # TLS_proxy
            flag("--cert", "cert")
            flag("--key", "key")
            flag("--ca", "ca")
            switch("--insecure", "insecure")
            switch("--verify-peer", "verify_peer")
            flag("--timeout-ms", "timeout_ms")
            switch("--verbose", "verbose")
            switch("--log-keys", "log_keys")

    elif binary == "dummy_station":
        role = f.get("role")
        if role not in ("master", "outstation"):
            errors.append("role must be 'master' or 'outstation'")
        else:
            argv.extend(["--role", role])
        flag("--listen-host", "listen_host")
        flag("--listen-port", "listen_port")
        flag("--connect-host", "connect_host")
        flag("--connect-port", "connect_port")
        flag("--message", "message")
        flag("--count", "count")
        flag("--interval-ms", "interval_ms")
    else:
        errors.append("unknown binary %r" % (binary,))

    extra = (f.get("extra_flags") or "").strip()
    if extra:
        try:
            argv.extend(shlex.split(extra))
        except ValueError as e:
            errors.append("could not parse extra flags: %s" % e)

    return argv, errors


def start_process(binary, argv):
    global NEXT_PROC_ID
    os.makedirs(LOG_DIR, exist_ok=True)
    exe_path = os.path.join(BIN_DIR, exe_name(binary))
    with PROCS_LOCK:
        pid_slot = NEXT_PROC_ID
        NEXT_PROC_ID += 1
    log_path = os.path.join(LOG_DIR, "%03d-%s.log" % (pid_slot, binary))
    log_f = open(log_path, "wb", buffering=0)
    full_argv = [exe_path] + argv
    popen = subprocess.Popen(full_argv, cwd=BIN_DIR or ".", stdout=log_f, stderr=subprocess.STDOUT)
    entry = {
        "id": pid_slot,
        "binary": binary,
        "argv": full_argv,
        "popen": popen,
        "log_path": log_path,
        "log_f": log_f,
        "started_at": time.time(),
    }
    with PROCS_LOCK:
        PROCS[pid_slot] = entry
    return entry


def tail_file(path, max_bytes=131072):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
            data = f.read()
        return data.decode("utf-8", errors="replace")
    except OSError as e:
        return "(could not read log: %s)" % e


def proc_status(entry):
    rc = entry["popen"].poll()
    return "running" if rc is None else ("exited(%s)" % rc)


PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SAv6 Proxy - Launcher</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 1000px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
  fieldset { border: 1px solid #ccc; border-radius: 6px; margin: 0.8rem 0; padding: 0.8rem 1rem; }
  legend { font-weight: 600; padding: 0 0.4rem; }
  label { display: inline-block; min-width: 220px; margin: 0.25rem 0; vertical-align: top; }
  input[type=text], input[type=number] { padding: 0.25rem; border: 1px solid #bbb; border-radius: 4px; width: 220px; }
  textarea { width: 100%; font-family: monospace; font-size: 0.85rem; }
  .row { margin: 0.2rem 0; }
  button { padding: 0.35rem 0.8rem; border: 1px solid #888; border-radius: 4px; background: #fff; cursor: pointer; }
  button:hover { background: #eee; }
  button.danger { color: #a00; border-color: #a00; }
  table { border-collapse: collapse; width: 100%; margin: 0.6rem 0; }
  th, td { border: 1px solid #ccc; padding: 0.35rem 0.5rem; font-size: 0.85rem; text-align: left; vertical-align: top; }
  th { background: #f4f4f4; }
  #status, #reginfo { font-size: 0.85rem; color: #444; white-space: pre-wrap; background: #f8f8f8;
                       border: 1px solid #ddd; border-radius: 4px; padding: 0.5rem; margin-top: 0.5rem; }
  pre#log { background: #111; color: #ddd; padding: 0.6rem; border-radius: 6px; max-height: 400px; overflow: auto;
            font-size: 0.78rem; white-space: pre-wrap; }
  code { background: #f4f4f4; padding: 0 0.3rem; border-radius: 3px; }
  select { padding: 0.3rem; }
</style>
</head>
<body>
<h1>SAv6 Proxy - Launcher</h1>
<p>Starts local processes (SAv6_proxy / TLS_proxy / dummy_station) with whatever flags you choose here.
This is the same thing as typing the command by hand -- it doesn't replace the CLI, and doesn't touch
any other host. Detected local IP: <code id="localip">...</code> (use this to advertise this host to a master).</p>

<form id="launchForm">
  <fieldset>
    <legend>Program</legend>
    <div class="row">
      <label>Binary</label>
      <select id="binary" onchange="onBinaryChange()">
        <option value="SAv6_proxy">SAv6_proxy</option>
        <option value="TLS_proxy">TLS_proxy</option>
        <option value="dummy_station">dummy_station</option>
      </select>
    </div>
    <div class="row" id="modeRow">
      <label>--mode / --role</label>
      <select id="mode" onchange="onModeChange()">
        <option value="master">master</option>
        <option value="outstation">outstation</option>
      </select>
    </div>
  </fieldset>

  <fieldset>
    <legend>Networking</legend>
    <div class="row"><label>--listen-host</label><input type="text" id="listen_host" placeholder="0.0.0.0 (default: all interfaces)"></div>
    <div class="row"><label>--listen-port</label><input type="text" id="listen_port" placeholder="e.g. 20000"></div>
    <div class="row"><label>--connect-host</label><input type="text" id="connect_host" placeholder="e.g. 192.168.1.50"></div>
    <div class="row"><label>--connect-port</label><input type="text" id="connect_port" placeholder="e.g. 20001"></div>
    <div class="row" id="routesRow">
      <label>--route (one per line, PORT:HOST:PORT)<br><small>overrides listen/connect-port above if filled in</small></label>
      <textarea id="routes" rows="3" style="width:220px" placeholder="19991:1.2.3.4:30000&#10;19992:1.2.3.5:30000"></textarea>
    </div>
  </fieldset>

  <fieldset id="cryptoFieldset">
    <legend>Crypto / rekey (SAv6_proxy)</legend>
    <div class="row"><label><input type="checkbox" id="ml_kem"> --ml-kem</label></div>
    <div class="row"><label>--update-rekey-messages</label><input type="text" id="update_rekey_messages" placeholder="0 = disabled"></div>
    <div class="row"><label>--session-rekey-messages</label><input type="text" id="session_rekey_messages" placeholder="0 = disabled"></div>
  </fieldset>

  <fieldset id="tlsFieldset">
    <legend>TLS options (TLS_proxy)</legend>
    <div class="row"><label>--cert</label><input type="text" id="cert" placeholder="path/to/cert.pem"></div>
    <div class="row"><label>--key</label><input type="text" id="key" placeholder="path/to/key.pem"></div>
    <div class="row"><label>--ca</label><input type="text" id="ca" placeholder="path/to/ca.pem"></div>
    <div class="row"><label><input type="checkbox" id="insecure" checked> --insecure</label></div>
    <div class="row"><label><input type="checkbox" id="verify_peer"> --verify-peer</label></div>
    <div class="row"><label>--timeout-ms</label><input type="text" id="timeout_ms" placeholder="0 = blocking"></div>
    <div class="row"><label><input type="checkbox" id="verbose"> --verbose</label></div>
    <div class="row"><label><input type="checkbox" id="log_keys"> --log-keys</label></div>
    <div class="row"><label><input type="checkbox" id="ml_kem_tls"> --ml-kem</label></div>
  </fieldset>

  <fieldset id="adminFieldset">
    <legend>Admin control channel (this process)</legend>
    <div class="row"><label>--control-host</label><input type="text" id="control_host" placeholder="127.0.0.1 default"></div>
    <div class="row"><label>--control-port</label><input type="text" id="control_port" placeholder="e.g. 9000 (enables it)"></div>
  </fieldset>

  <fieldset id="stationFieldset">
    <legend>dummy_station options</legend>
    <div class="row"><label>--message</label><input type="text" id="message"></div>
    <div class="row"><label>--count</label><input type="text" id="count"></div>
    <div class="row"><label>--interval-ms</label><input type="text" id="interval_ms"></div>
  </fieldset>

  <fieldset id="registerFieldset">
    <legend>Register this outstation with a master (optional)</legend>
    <p style="font-size:0.85rem;color:#555;margin:0.2rem 0 0.6rem;">
      An outstation never announces itself -- the master always initiates. Leave this blank and you'll
      just get the manual command to run yourself; fill it in and this UI will call the master's admin
      channel for you right after starting.</p>
    <div class="row"><label>Master admin (host:port)</label><input type="text" id="master_admin" placeholder="e.g. 192.168.1.16:9000"></div>
    <div class="row"><label>New listen port on master</label><input type="text" id="master_new_port" placeholder="e.g. 19994"></div>
    <div class="row"><label>Advertise this outstation as</label><input type="text" id="advertise_host" placeholder="auto-filled from detected IP"></div>
  </fieldset>

  <fieldset>
    <legend>Anything else</legend>
    <div class="row"><label>Extra raw flags</label><input type="text" id="extra_flags" style="width:400px" placeholder="--any-flag value ..."></div>
  </fieldset>

  <button type="submit">Start</button>
</form>
<div id="status"></div>
<div id="reginfo"></div>

<h2>Running / recent processes</h2>
<table id="procs"><thead><tr><th>ID</th><th>Binary</th><th>Command</th><th>Status</th><th>Started</th><th></th></tr></thead><tbody></tbody></table>

<h2>Log <span id="logTitle"></span></h2>
<pre id="log">(select "View log" on a process above)</pre>

<script>
let watchingLogId = null;

function onBinaryChange() {
  const b = document.getElementById('binary').value;
  document.getElementById('cryptoFieldset').style.display = (b === 'SAv6_proxy') ? '' : 'none';
  document.getElementById('tlsFieldset').style.display = (b === 'TLS_proxy') ? '' : 'none';
  document.getElementById('adminFieldset').style.display = (b === 'dummy_station') ? 'none' : '';
  document.getElementById('routesRow').style.display = (b === 'dummy_station') ? 'none' : '';
  document.getElementById('stationFieldset').style.display = (b === 'dummy_station') ? '' : 'none';
  document.getElementById('modeRow').querySelector('label').textContent = (b === 'dummy_station') ? '--role' : '--mode';
  onModeChange();
}

function onModeChange() {
  const b = document.getElementById('binary').value;
  const mode = document.getElementById('mode').value;
  const showRegister = (b !== 'dummy_station') && mode === 'outstation';
  document.getElementById('registerFieldset').style.display = showRegister ? '' : 'none';
}

async function loadLocalIp() {
  const r = await fetch('/api/localip');
  const j = await r.json();
  document.getElementById('localip').textContent = j.ip;
  document.getElementById('advertise_host').placeholder = j.ip + ':<listen_port>';
}

function fieldVal(id) {
  const el = document.getElementById(id);
  if (!el) return undefined;
  if (el.type === 'checkbox') return el.checked;
  return el.value;
}

document.getElementById('launchForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const binary = document.getElementById('binary').value;
  const payload = {
    binary: binary,
    mode: fieldVal('mode'),
    role: fieldVal('mode'),
    listen_host: fieldVal('listen_host'),
    listen_port: fieldVal('listen_port'),
    connect_host: fieldVal('connect_host'),
    connect_port: fieldVal('connect_port'),
    routes: fieldVal('routes'),
    ml_kem: binary === 'TLS_proxy' ? fieldVal('ml_kem_tls') : fieldVal('ml_kem'),
    update_rekey_messages: fieldVal('update_rekey_messages'),
    session_rekey_messages: fieldVal('session_rekey_messages'),
    cert: fieldVal('cert'), key: fieldVal('key'), ca: fieldVal('ca'),
    insecure: fieldVal('insecure'), verify_peer: fieldVal('verify_peer'),
    timeout_ms: fieldVal('timeout_ms'), verbose: fieldVal('verbose'), log_keys: fieldVal('log_keys'),
    control_host: fieldVal('control_host'), control_port: fieldVal('control_port'),
    message: fieldVal('message'), count: fieldVal('count'), interval_ms: fieldVal('interval_ms'),
    extra_flags: fieldVal('extra_flags'),
    master_admin: fieldVal('master_admin'),
    master_new_port: fieldVal('master_new_port'),
    advertise_host: fieldVal('advertise_host'),
  };
  const r = await fetch('/api/start', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
  });
  const j = await r.json();
  const statusEl = document.getElementById('status');
  const regEl = document.getElementById('reginfo');
  regEl.textContent = '';
  if (j.error) {
    statusEl.textContent = 'Error: ' + j.error;
  } else {
    statusEl.textContent = 'Started process ' + j.id + ': ' + j.argv.join(' ');
    if (j.registration) {
      regEl.textContent = 'Master registration: ' + j.registration;
    }
    if (j.manual_add) {
      regEl.textContent += (regEl.textContent ? '\\n\\n' : '') + 'To add manually later:\\n' + j.manual_add;
    }
  }
  refreshProcs();
});

async function refreshProcs() {
  const r = await fetch('/api/procs');
  const j = await r.json();
  const tbody = document.querySelector('#procs tbody');
  tbody.innerHTML = j.procs.map(p => `
    <tr>
      <td>${p.id}</td>
      <td>${p.binary}</td>
      <td><code style="font-size:0.75rem">${p.argv.join(' ')}</code></td>
      <td>${p.status}</td>
      <td>${new Date(p.started_at * 1000).toLocaleTimeString()}</td>
      <td>
        <button onclick="viewLog(${p.id})">View log</button>
        ${p.status === 'running' ? `<button class="danger" onclick="stopProc(${p.id})">Stop</button>` : ''}
      </td>
    </tr>`).join('');
}

async function viewLog(id) {
  watchingLogId = id;
  document.getElementById('logTitle').textContent = '(process ' + id + ')';
  await pollLog();
}

async function pollLog() {
  if (watchingLogId === null) return;
  const r = await fetch('/api/log?id=' + watchingLogId);
  const j = await r.json();
  const pre = document.getElementById('log');
  pre.textContent = j.log || j.error || '';
  pre.scrollTop = pre.scrollHeight;
}

async function stopProc(id) {
  if (!confirm('Stop process ' + id + '?')) return;
  await fetch('/api/stop', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id: id})
  });
  refreshProcs();
}

onBinaryChange();
loadLocalIp();
refreshProcs();
setInterval(refreshProcs, 4000);
setInterval(pollLog, 3000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/":
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/api/localip":
            self._json({"ip": detect_local_ip()})
        elif parsed.path == "/api/procs":
            with PROCS_LOCK:
                procs = [{
                    "id": e["id"], "binary": e["binary"], "argv": e["argv"],
                    "status": proc_status(e), "started_at": e["started_at"],
                } for e in PROCS.values()]
            procs.sort(key=lambda p: p["id"])
            self._json({"procs": procs})
        elif parsed.path == "/api/log":
            pid = int(qs.get("id", ["0"])[0])
            with PROCS_LOCK:
                e = PROCS.get(pid)
            if not e:
                self._json({"error": "no such process %d" % pid}, 404)
                return
            self._json({"log": tail_file(e["log_path"])})
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json({"error": "bad json"}, 400)
            return

        if parsed.path == "/api/start":
            self._handle_start(payload)
        elif parsed.path == "/api/stop":
            self._handle_stop(payload)
        else:
            self.send_error(404)

    def _handle_start(self, f):
        binary = f.get("binary")
        argv, errors = build_argv(binary, f)
        if errors:
            self._json({"error": "; ".join(errors)}, 400)
            return

        try:
            entry = start_process(binary, argv)
        except OSError as e:
            self._json({"error": "failed to start %s: %s" % (binary, e)}, 500)
            return

        result = {"id": entry["id"], "argv": entry["argv"]}

        if binary in ("SAv6_proxy", "TLS_proxy") and f.get("mode") == "outstation":
            listen_port = f.get("listen_port") or (
                (f.get("routes") or "").splitlines()[0].split(":")[0] if f.get("routes") else None
            )
            advertise_host = (f.get("advertise_host") or "").strip() or detect_local_ip()
            if listen_port:
                manual_target = "%s:%s" % (advertise_host, listen_port)
                master_admin = (f.get("master_admin") or "").strip()
                master_new_port = (f.get("master_new_port") or "").strip()
                bin_display = "./" + exe_name(binary)
                result["manual_add"] = (
                    "%s --admin MASTER_ADMIN_HOST:PORT --add NEW_PORT:%s\n"
                    "  (or add --route NEW_PORT:%s to the master's launch command)"
                ) % (bin_display, manual_target, manual_target)

                if master_admin and master_new_port:
                    try:
                        host, port = master_admin.rsplit(":", 1)
                        spec = "%s:%s:%s" % (master_new_port, advertise_host, listen_port)
                        time.sleep(1.0)  # give the just-started listener a moment to bind
                        resp = send_admin_command(host, port, "ADD " + spec)
                        result["registration"] = resp.strip()
                    except (OSError, ValueError) as e:
                        result["registration"] = "failed: %s" % e

        self._json(result)

    def _handle_stop(self, f):
        pid = f.get("id")
        with PROCS_LOCK:
            e = PROCS.get(pid)
        if not e:
            self._json({"error": "no such process %r" % (pid,)}, 404)
            return
        try:
            e["popen"].terminate()
        except OSError as ex:
            self._json({"error": str(ex)}, 500)
            return
        self._json({"result": "stopping"})

    def log_message(self, fmt, *args):
        sys.stderr.write("[launch-ui] " + (fmt % args) + "\n")


def main():
    global BIN_DIR
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin-dir", default=".", help="directory containing the built binaries (default: .)")
    ap.add_argument("--listen", default="127.0.0.1:8766", metavar="HOST:PORT",
                     help="address for this web UI to bind (default 127.0.0.1:8766)")
    args = ap.parse_args()
    BIN_DIR = args.bin_dir

    lhost, lport = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((lhost, int(lport)), Handler)
    print("[launch-ui] serving on http://%s:%s/ (binaries in %s)" % (lhost, lport, os.path.abspath(BIN_DIR)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
