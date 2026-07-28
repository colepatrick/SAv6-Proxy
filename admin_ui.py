#!/usr/bin/env python3
"""
Minimal, dependency-free web UI for the SAv6_proxy / TLS_proxy admin control
channel (ADD/REMOVE/LIST over the small TCP text protocol described in
README.md). This does NOT replace or disable the CLI admin client
(`--admin HOST:PORT --list/--add/--remove`) -- it is just another client of
the same protocol, for quicker testing, configuring, and demoing. It does not
start or stop proxy processes itself; a proxy must already be running with
--control-port for this to talk to it.

Usage:
  python3 admin_ui.py --instance master=127.0.0.1:9000 [--instance other=127.0.0.1:9001 ...] [--listen 0.0.0.0:8765]

Then open http://<this-host>:8765/ in a browser.

Security note: the admin control protocol has no authentication. Keep each
proxy's --control-host on loopback (the default) and run this bridge on the
SAME host as the proxy/proxies it talks to -- only the web UI itself should
be exposed beyond loopback, and only on networks you trust, since it also
has no authentication of its own.
"""
import argparse
import json
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

INSTANCES = {}  # name -> (host, port)


def send_admin_command(host, port, command, timeout=5.0):
    with socket.create_connection((host, port), timeout=timeout) as s:
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


def parse_list_output(text):
    routes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line == ".":
            continue
        # "<id> <role> <listen_port> -> <connect_host>:<connect_port>"
        try:
            rid, role, listen_port, _arrow, target = line.split(None, 4)
            connect_host, connect_port = target.rsplit(":", 1)
            routes.append({
                "id": int(rid),
                "role": role,
                "listen_port": listen_port,
                "connect_host": connect_host,
                "connect_port": connect_port,
            })
        except ValueError:
            continue
    return routes


PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SAv6 Proxy - Route Admin</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  h1 { font-size: 1.4rem; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }
  th { background: #f4f4f4; }
  form.add-row { display: flex; gap: 0.5rem; margin: 1rem 0; flex-wrap: wrap; align-items: center; }
  form.add-row input { padding: 0.3rem; border: 1px solid #bbb; border-radius: 4px; }
  button { padding: 0.3rem 0.7rem; border: 1px solid #888; border-radius: 4px; background: #fff; cursor: pointer; }
  button:hover { background: #eee; }
  button.remove { color: #a00; border-color: #a00; }
  #status { font-size: 0.85rem; color: #666; min-height: 1.2em; }
  select { padding: 0.3rem; }
  code { background: #f4f4f4; padding: 0 0.3rem; border-radius: 3px; }
</style>
</head>
<body>
<h1>SAv6 Proxy - Route Admin</h1>
<p>Talks to the proxy's admin control channel (ADD/REMOVE/LIST). The CLI
(<code>--admin HOST:PORT --list/--add/--remove</code>) still works exactly the same way;
this page is just another client of the same protocol.</p>
<p>Instance: <select id="instance"></select> <button onclick="refresh()">Refresh</button></p>
<p id="modeNote" style="font-size:0.9rem;color:#555;"></p>
<table id="routes">
  <thead><tr><th>ID</th><th>Listen Port</th><th id="connectHeader">Connects to</th><th></th></tr></thead>
  <tbody></tbody>
</table>
<form class="add-row" onsubmit="addRoute(event)">
  <strong>Add route:</strong>
  <input id="listen_port" placeholder="listen port" required size="10">
  <input id="connect_host" placeholder="connect host" required size="16">
  <input id="connect_port" placeholder="connect port" required size="10">
  <button type="submit">Add</button>
</form>
<div id="status"></div>

<script>
let instances = [];

async function loadInstances() {
  const r = await fetch('/api/instances');
  const j = await r.json();
  instances = j.instances;
  const sel = document.getElementById('instance');
  sel.innerHTML = instances.map(n => `<option value="${n}">${n}</option>`).join('');
  sel.onchange = refresh;
}

function currentInstance() {
  return document.getElementById('instance').value;
}

async function refresh() {
  const inst = currentInstance();
  if (!inst) return;
  const r = await fetch(`/api/list?instance=${encodeURIComponent(inst)}`);
  const j = await r.json();
  const tbody = document.querySelector('#routes tbody');
  if (j.error) {
    document.getElementById('status').textContent = 'Error: ' + j.error;
    tbody.innerHTML = '';
    return;
  }
  document.getElementById('status').textContent =
    `${j.routes.length} route(s) on "${inst}" - last updated ${new Date().toLocaleTimeString()}`;

  // Every route on one proxy process shares the same role (a process is
  // entirely master-side or entirely outstation-side, never mixed), so show
  // it once for the instance instead of repeating a confusing column.
  const role = j.routes.length ? j.routes[0].role : null;
  const modeNote = document.getElementById('modeNote');
  const connectHeader = document.getElementById('connectHeader');
  if (role === 'master') {
    modeNote.textContent = 'This instance is a master-side proxy: each row is a local plaintext port paired with one outstation-side proxy.';
    connectHeader.textContent = 'Connects to (outstation-side proxy)';
  } else if (role === 'outstation') {
    modeNote.textContent = 'This instance is an outstation-side proxy: each row is a secure listen port paired with one local plaintext device.';
    connectHeader.textContent = 'Connects to (local device)';
  } else {
    modeNote.textContent = '';
    connectHeader.textContent = 'Connects to';
  }

  tbody.innerHTML = j.routes.map(rt => `
    <tr>
      <td>${rt.id}</td>
      <td>${rt.listen_port}</td>
      <td>${rt.connect_host}:${rt.connect_port}</td>
      <td><button class="remove" onclick="removeRoute(${rt.id})">Remove</button></td>
    </tr>`).join('');
}

async function addRoute(ev) {
  ev.preventDefault();
  const body = {
    listen_port: document.getElementById('listen_port').value,
    connect_host: document.getElementById('connect_host').value,
    connect_port: document.getElementById('connect_port').value,
  };
  const inst = currentInstance();
  const r = await fetch(`/api/add?instance=${encodeURIComponent(inst)}`, {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
  });
  const j = await r.json();
  document.getElementById('status').textContent = j.error ? ('Error: ' + j.error) : ('Add: ' + j.result);
  ev.target.reset();
  refresh();
}

async function removeRoute(id) {
  if (!confirm(`Remove route ${id}?`)) return;
  const inst = currentInstance();
  const r = await fetch(`/api/remove?instance=${encodeURIComponent(inst)}`, {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id: id})
  });
  const j = await r.json();
  document.getElementById('status').textContent = j.error ? ('Error: ' + j.error) : ('Remove: ' + j.result);
  refresh();
}

loadInstances().then(refresh);
setInterval(refresh, 4000);
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

    def _instance(self, qs):
        name = (qs.get("instance", [None])[0]) or (next(iter(INSTANCES), None))
        if not name or name not in INSTANCES:
            return None, name
        return INSTANCES[name], name

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
        elif parsed.path == "/api/instances":
            self._json({"instances": list(INSTANCES.keys())})
        elif parsed.path == "/api/list":
            inst, name = self._instance(qs)
            if not inst:
                self._json({"error": "unknown instance %r" % (name,)}, 400)
                return
            try:
                text = send_admin_command(inst[0], inst[1], "LIST")
                self._json({"routes": parse_list_output(text)})
            except OSError as e:
                self._json({"error": str(e)}, 502)
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json({"error": "bad json"}, 400)
            return

        inst, name = self._instance(qs)
        if not inst:
            self._json({"error": "unknown instance %r" % (name,)}, 400)
            return

        if parsed.path == "/api/add":
            spec = "%s:%s:%s" % (
                payload.get("listen_port", ""),
                payload.get("connect_host", ""),
                payload.get("connect_port", ""),
            )
            try:
                text = send_admin_command(inst[0], inst[1], "ADD %s" % spec)
                self._json({"result": text.strip()})
            except OSError as e:
                self._json({"error": str(e)}, 502)
        elif parsed.path == "/api/remove":
            rid = payload.get("id")
            try:
                text = send_admin_command(inst[0], inst[1], "REMOVE %s" % rid)
                self._json({"result": text.strip()})
            except OSError as e:
                self._json({"error": str(e)}, 502)
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        sys.stderr.write("[admin-ui] " + (fmt % args) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--instance", action="append", default=[], metavar="NAME=HOST:PORT",
                     help="admin control channel to manage; repeatable (default: master=127.0.0.1:9000)")
    ap.add_argument("--listen", default="127.0.0.1:8765", metavar="HOST:PORT",
                     help="address for this web UI to bind (default 127.0.0.1:8765)")
    args = ap.parse_args()

    for item in (args.instance or ["master=127.0.0.1:9000"]):
        try:
            name, hostport = item.split("=", 1)
            host, port = hostport.rsplit(":", 1)
            INSTANCES[name] = (host, int(port))
        except ValueError:
            sys.exit("bad --instance %r, expected NAME=HOST:PORT" % (item,))

    lhost, lport = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((lhost, int(lport)), Handler)
    print("[admin-ui] serving on http://%s:%s/ for instances: %s" % (lhost, lport, ", ".join(INSTANCES)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
