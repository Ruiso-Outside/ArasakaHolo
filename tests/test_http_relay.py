"""
Teste do modo HTTP do cliente: dois clientes entram numa sala, trocam mensagem cifrada e mandam uma mensagem direta.

    python tests/test_http_relay.py                     copia em Python (em memoria) do relay
    python tests/test_http_relay.py --php [php]         o relay-php/index.php de verdade, com o servidor do PHP
"""
from __future__ import annotations

import json
import os
import queue
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["HOME"] = tempfile.mkdtemp()            # identidades de teste, fora do perfil real

from arasaka_holo import crypto                       # noqa: E402
from arasaka_holo.identity import Identity, valid_nick   # noqa: E402
from arasaka_holo.net import HoloClient               # noqa: E402
from nacl.signing import SigningKey                   # noqa: E402

POW = 8   # prova de trabalho leve no teste


class Relay:
    """Mesmas regras do index.php, em memoria."""

    def __init__(self):
        self.lock = threading.Lock()
        self.host = ""
        self.challenges, self.nicks, self.sessions, self.rooms, self.queues = set(), {}, {}, {}, {}

    def handle(self, m: dict) -> dict:
        op = m.get("op")
        with self.lock:
            if op == "hello":
                ch = secrets.token_hex(16)
                self.challenges.add(ch)
                return {"op": "hello", "proto": 1, "challenge": ch, "pow": POW, "motd": "teste", "transport": "http",
                        "auth": 2}
            if op == "auth":
                ch, nick, pk = m.get("challenge"), m.get("nick", ""), m.get("pk", "")
                if ch not in self.challenges:
                    return {"op": "error", "code": "bad_auth", "msg": "desafio expirado"}
                self.challenges.discard(ch)
                if not valid_nick(nick):
                    return {"op": "error", "code": "bad_auth", "msg": "autenticacao invalida"}
                if self.nicks.get(nick, pk) != pk:
                    return {"op": "error", "code": "nick_taken", "msg": "este nick ja pertence a outra chave"}
                if not crypto.check_auth(pk, ch, nick, m.get("sig", ""), self.host, legacy=False):
                    return {"op": "error", "code": "bad_sig", "msg": "assinatura invalida"}
                new = nick not in self.nicks
                if new and not crypto.pow_ok(ch, nick, pk, int(m.get("pow", -1)), POW):
                    return {"op": "error", "code": "pow", "msg": "prova de trabalho invalida"}
                self.nicks[nick] = pk
                tok = secrets.token_hex(32)
                self.sessions[tok] = {"nick": nick, "pk": pk, "rooms": set()}
                self.queues[tok] = queue.Queue()
                return {"op": "welcome", "nick": nick, "new": new, "online": len(self.sessions), "token": tok}
            tok = m.get("token")
            s = self.sessions.get(tok)
            if not s:
                return {"op": "error", "code": "session", "msg": "sessao expirada"}
            if op == "send":
                out = []
                for x in m.get("msgs", []):
                    o = x.get("op")
                    if o == "join":
                        rid = x["room"]
                        s["rooms"].add(rid)
                        self.rooms.setdefault(rid, set()).add(tok)
                        out.append({"op": "joined", "room": rid, "members": sorted({self.sessions[t]["nick"] for t in self.rooms[rid]})})
                        for t in self.rooms[rid] - {tok}:
                            self.queues[t].put({"op": "presence", "room": rid, "nick": s["nick"], "on": True, "count": len(self.rooms[rid])})
                    elif o == "msg" and x["room"] in s["rooms"]:
                        for t in self.rooms[x["room"]]:
                            self.queues[t].put({"op": "msg", "room": x["room"], "blob": x["blob"]})
                    elif o == "dm":
                        targets = [t for t, v in self.sessions.items() if v["nick"] == x["to"]]
                        if not targets:
                            out.append({"op": "error", "code": "offline", "to": x["to"], "msg": "offline"})
                            continue
                        for t in targets:
                            self.queues[t].put({"op": "dm", "from": s["nick"], "from_pk": s["pk"], "blob": x["blob"]})
                        out.append({"op": "dm_ok", "to": x["to"], "ref": x.get("ref")})
                    elif o == "ping":
                        out.append({"op": "pong", "t": x.get("t")})
                return {"op": "sent", "events": out}
            if op == "bye":
                for rid in s["rooms"]:
                    self.rooms[rid].discard(tok)
                    for t in self.rooms[rid]:
                        self.queues[t].put({"op": "presence", "room": rid, "nick": s["nick"], "on": False, "count": 1})
                del self.sessions[tok]
                return {"op": "bye"}
            q = self.queues[tok]
        if op == "poll":
            evs = []
            try:
                evs.append(q.get(timeout=3))
                while not q.empty():
                    evs.append(q.get_nowait())
            except queue.Empty:
                pass
            return {"op": "events", "events": evs}
        return {"op": "error", "code": "bad_request", "msg": "?"}


RELAY = Relay()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        RELAY.host = crypto.host_id(self.headers["Host"])
        body = json.dumps(RELAY.handle(json.loads(self.rfile.read(n)))).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802   # pagina comum: o cliente nao pode confundir com um relay
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<html>site</html>")

    def log_message(self, *a):
        pass


def client(nick: str, url: str):
    ident = Identity(nick, SigningKey.generate(), "teste")
    events: list[dict] = []
    c = HoloClient(url, ident, events.append)
    c.start()
    return c, ident, events


def wait_for(events, pred, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        for e in list(events):
            if pred(e):
                return e
        time.sleep(0.1)
    raise AssertionError(f"evento nao chegou; recebidos: {[(e.get('op'), e.get('code') or e.get('error')) for e in events]}")


def exchange(url: str, php: bool):
    a, ia, ea = client("KuroiRonin-7F3A", url)
    b, ib, eb = client("AkaiShogun-01BC", url)
    ec: list[dict] = []
    try:
        w = wait_for(ea, lambda e: e.get("op") == "welcome")
        wait_for(eb, lambda e: e.get("op") == "welcome")
        rid = "sala-teste-hash"
        a.send({"op": "join", "room": rid})
        wait_for(ea, lambda e: e.get("op") == "joined")
        b.send({"op": "join", "room": rid})
        wait_for(eb, lambda e: e.get("op") == "joined" and set(e["members"]) == {ia.nick, ib.nick})
        wait_for(ea, lambda e: e.get("op") == "presence" and e["nick"] == ib.nick)
        a.send({"op": "msg", "room": rid, "blob": "BLOB-CIFRADO-123"})
        wait_for(eb, lambda e: e.get("op") == "msg" and e["blob"] == "BLOB-CIFRADO-123")
        big = "S" * 14000                                       # tamanho de uma sinalizacao de call
        a.send({"op": "dm", "to": ib.nick, "blob": big, "ref": 7})
        wait_for(eb, lambda e: e.get("op") == "dm" and e["from"] == ia.nick and e["blob"] == big)
        wait_for(ea, lambda e: e.get("op") == "dm_ok" and e.get("ref") == 7)
        a.send({"op": "dm", "to": "NinguemAqui-0000", "blob": "x"})
        wait_for(ea, lambda e: e.get("op") == "error" and e.get("code") == "offline")
        if php:
            assert w["new"] and w["ice"][0]["urls"][0].startswith("stun:"), w
            a.send({"op": "ice"})
            wait_for(ea, lambda e: e.get("op") == "ice" and e["servers"])
            a.send({"op": "whois", "nick": ib.nick})
            wait_for(ea, lambda e: e.get("op") == "whois" and e["pk"] == ib.pk_b64 and e["online"])
            thief = HoloClient(url, Identity(ia.nick, SigningKey.generate(), "t"), ec.append)
            thief.start()
            wait_for(ec, lambda e: e.get("code") == "nick_taken")
            thief.stop()
            for _ in range(40):
                a.send({"op": "msg", "room": rid, "blob": "flood"})
            wait_for(ea, lambda e: e.get("code") == "rate")
        t0 = time.time()
        b.stop()
        wait_for(ea, lambda e: e.get("op") == "presence" and e["nick"] == ib.nick and not e["on"], 8)   # op bye
        assert time.time() - t0 < 8
    finally:
        a.stop()
        b.stop()


def post(url: str, data) -> dict:
    import urllib.error
    import urllib.request
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, raw), timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def php_attacks(url: str, data: str):
    """O que um cliente modificado poderia tentar contra o relay PHP."""
    import urllib.request
    sk = SigningKey.generate()
    pk = crypto.b64(bytes(sk.verify_key))
    host = crypto.url_host(url)

    def login(nick, host=host, ch=None, legacy=False):
        ch = ch or post(url, {"op": "hello"})["challenge"]
        sig = crypto.auth_signature(sk, ch, nick, host) if not legacy else \
            crypto.b64(sk.sign(f"HOLO-AUTH|{ch}|{nick}".encode()).signature)
        return post(url, {"op": "auth", "challenge": ch, "nick": nick, "pk": pk, "sig": sig,
                          "pow": crypto.solve_pow(ch, nick, pk)}), ch
    assert login("KuroiRonin-7F3A\n")[0]["code"] == "bad_auth", "nick com quebra de linha"
    assert login("GhostOni-AAAA", host="outro.com")[0]["code"] == "bad_sig", "assinatura de outro servidor"
    ok, ch = login("GhostOni-AAAA")
    assert ok["op"] == "welcome", ok
    assert login("GhostOni-AAAA", ch=ch)[0]["code"] == "challenge", "desafio reutilizado"
    assert login("GhostOni-AAAA", ch="f" * 64)[0]["code"] == "challenge", "desafio inventado"
    assert login("GhostOni-AAAA", legacy=True)[0]["op"] == "welcome", "HOLO 1.1 ainda entra"
    ch = post(url, {"op": "hello"})["challenge"]
    r = post(url, {"op": "auth", "challenge": ch, "nick": "VoidRaven-0001", "pk": pk, "pow": 0,
                   "sig": crypto.auth_signature(sk, ch, "VoidRaven-0001", host)})
    assert r["code"] == "pow", r
    tok = ok["token"]
    for junk in (b"", b"[]", b"1", b"{", b'{"op":[]}', b'{"op":"auth","nick":[],"pk":{},"sig":1,"challenge":[]}',
                 b'{"op":"send","token":[1]}', b'{"op":"poll","token":{}}', b'{"op":"bye","token":null}'):
        assert post(url, junk).get("op") == "error" or post(url, junk).get("op") == "bye", junk
    r = post(url, {"op": "send", "token": tok, "msgs": [1, None, {"op": "join", "room": []}, {"op": "msg", "room": "z", "blob": "x"},
                                                         {"op": "dm", "to": {}, "blob": []}, {"op": "whois", "nick": []}]})
    assert r["op"] == "sent", r
    assert post(url, {"op": "send", "token": "0" * 64, "msgs": []})["code"] == "session"
    r = post(url, {"op": "send", "token": tok, "msgs": [{"op": "msg", "room": "z", "blob": "A" * 33000}]})
    assert r["events"][0]["code"] == "too_big", r
    assert post(url, {"op": "bye", "token": tok})["op"] == "bye"
    assert post(url, {"op": "poll", "token": tok})["code"] == "session", "sessao encerrada nao volta"
    for page in ("", "?check"):
        html = urllib.request.urlopen(url + page, timeout=10).read().decode()
        assert "HOLO RELAY" in html and "Warning" not in html and "Fatal" not in html, html
    files = [os.path.join(d, f) for d, _s, fs in os.walk(data) for f in fs]
    blob = b"".join(open(f, "rb").read() for f in files)
    assert b"127.0.0.1" not in blob, "gravou IP"
    assert not [f for f in files if f.endswith(".q") and os.path.getsize(f)], "sobrou mensagem no disco"


def cgi_server(php: str, root: str, env: dict, log: str) -> ThreadingHTTPServer:
    """Windows: um php-cgi por requisicao (o servidor embutido do PHP so atende uma por vez ali)."""
    folder = os.path.dirname(os.path.abspath(php))
    cmd = [os.path.join(folder, "php-cgi.exe")]
    ini = os.path.dirname(log)                     # em modo CGI o PHP ignora as opcoes -d
    with open(os.path.join(ini, "php.ini"), "w") as f:
        f.write(f'extension_dir="{os.path.join(folder, "ext")}"\nextension=sodium\nlog_errors=1\nerror_log="{log}"\n'
                'error_reporting=32767\n')
    env = {**env, "PHPRC": ini}

    class Cgi(BaseHTTPRequestHandler):
        def run(self):
            n = int(self.headers.get("Content-Length") or 0)
            path, _, query = self.path.partition("?")
            e = {**env, "GATEWAY_INTERFACE": "CGI/1.1", "REDIRECT_STATUS": "200", "SERVER_PROTOCOL": "HTTP/1.1",
                 "REQUEST_METHOD": self.command, "REQUEST_URI": self.path, "QUERY_STRING": query, "SCRIPT_NAME": path,
                 "SCRIPT_FILENAME": os.path.join(root, "index.php"), "DOCUMENT_ROOT": root, "CONTENT_LENGTH": str(n),
                 "CONTENT_TYPE": self.headers.get("Content-Type", ""), "HTTP_HOST": self.headers["Host"],
                 "REMOTE_ADDR": "127.0.0.1", "SERVER_PORT": str(self.server.server_address[1])}
            out = subprocess.run(cmd, input=self.rfile.read(n), env=e, capture_output=True, timeout=60).stdout
            head, _, body = out.partition(b"\r\n\r\n")
            status, heads = 200, []
            for ln in head.decode("latin-1").split("\r\n"):
                k, _, v = ln.partition(": ")
                if k.lower() == "status":
                    status = int(v.split()[0])
                elif v:
                    heads.append((k, v))
            self.send_response(status)
            for k, v in heads + [("Content-Length", str(len(body)))]:
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass
        do_GET = do_POST = run  # noqa: N815

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Cgi)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_php(php: str):
    tmp = tempfile.mkdtemp()
    data, log = os.path.join(tmp, "d"), os.path.join(tmp, "log")
    open(log, "w").close()
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "relay-php"))
    env = {**os.environ, "HOLO_DATA": data, "PHP_CLI_SERVER_WORKERS": "12"}
    proc = srv = None
    if os.name == "nt":
        srv = cgi_server(php, root, env, log)
        port = srv.server_address[1]
    else:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        f = open(log, "ab")
        proc = subprocess.Popen([php, "-d", "log_errors=1", "-d", "error_reporting=32767", "-S", f"127.0.0.1:{port}", "-t", root],
                                env=env, stdout=f, stderr=f, start_new_session=True)
    url = f"http://127.0.0.1:{port}/"
    try:
        for _ in range(50):
            try:
                post(url, {"op": "info"})
                break
            except OSError:
                time.sleep(0.2)
        exchange(url, True)
        time.sleep(1)
        php_attacks(url, data)
    finally:
        if proc:
            os.killpg(proc.pid, 15)
            proc.wait()
        if srv:
            srv.shutdown()
    text = open(log, encoding="utf-8", errors="replace").read()
    bad = [ln for ln in text.splitlines() if "PHP " in ln and any(w in ln for w in ("Warning", "Fatal", "Notice", "Deprecated"))]
    assert not bad, bad[:5]
    print("OK: relay PHP de verdade (login, sala, mensagens, call, limites, ataques, sem IP e sem sobras no disco)")


def main():
    if "--php" in sys.argv:
        i = sys.argv.index("--php")
        php = sys.argv[i + 1] if len(sys.argv) > i + 1 else shutil.which("php")
        assert php, "php nao encontrado"
        return run_php(php)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    exchange(f"http://127.0.0.1:{srv.server_address[1]}/", False)
    srv.shutdown()
    print("OK: modo HTTP (login, sala, presenca, mensagem, mensagem direta, offline, saida)")


if __name__ == "__main__":
    main()
