"""
Teste do modo HTTP do cliente contra uma copia em Python (em memoria) do relay PHP (relay-php/index.php):
dois clientes entram numa sala, trocam mensagem cifrada e mandam uma mensagem direta.

    python tests/test_http_relay.py
"""
from __future__ import annotations

import json
import os
import queue
import secrets
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["HOME"] = tempfile.mkdtemp()            # identidades de teste, fora do perfil real

from arasaka_holo import crypto                       # noqa: E402
from arasaka_holo.identity import NICK_RE, Identity   # noqa: E402
from arasaka_holo.net import HoloClient               # noqa: E402
from nacl.signing import SigningKey                   # noqa: E402

POW = 8   # prova de trabalho leve no teste


class Relay:
    """Mesmas regras do index.php, em memoria."""

    def __init__(self):
        self.lock = threading.Lock()
        self.challenges, self.nicks, self.sessions, self.rooms, self.queues = set(), {}, {}, {}, {}

    def handle(self, m: dict) -> dict:
        op = m.get("op")
        with self.lock:
            if op == "hello":
                ch = secrets.token_hex(16)
                self.challenges.add(ch)
                return {"op": "hello", "proto": 1, "challenge": ch, "pow": POW, "motd": "teste", "transport": "http"}
            if op == "auth":
                ch, nick, pk = m.get("challenge"), m.get("nick", ""), m.get("pk", "")
                if ch not in self.challenges:
                    return {"op": "error", "code": "bad_auth", "msg": "desafio expirado"}
                self.challenges.discard(ch)
                if not NICK_RE.match(nick):
                    return {"op": "error", "code": "bad_auth", "msg": "autenticacao invalida"}
                if self.nicks.get(nick, pk) != pk:
                    return {"op": "error", "code": "nick_taken", "msg": "este nick ja pertence a outra chave"}
                if not crypto.check_auth(pk, ch, nick, m.get("sig", "")):
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
    raise AssertionError(f"evento nao chegou; recebidos: {[e.get('op') for e in events]}")


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    a, ia, ea = client("KuroiRonin-7F3A", url)
    b, ib, eb = client("AkaiShogun-01BC", url)
    try:
        wait_for(ea, lambda e: e.get("op") == "welcome")
        wait_for(eb, lambda e: e.get("op") == "welcome")
        rid = "sala-teste-hash"
        a.send({"op": "join", "room": rid})
        wait_for(ea, lambda e: e.get("op") == "joined")
        b.send({"op": "join", "room": rid})
        wait_for(eb, lambda e: e.get("op") == "joined" and set(e["members"]) == {ia.nick, ib.nick})
        wait_for(ea, lambda e: e.get("op") == "presence" and e["nick"] == ib.nick)
        a.send({"op": "msg", "room": rid, "blob": "BLOB-CIFRADO-123"})
        wait_for(eb, lambda e: e.get("op") == "msg" and e["blob"] == "BLOB-CIFRADO-123")
        a.send({"op": "dm", "to": ib.nick, "blob": "DM-CIFRADA", "ref": 7})
        wait_for(eb, lambda e: e.get("op") == "dm" and e["from"] == ia.nick and e["blob"] == "DM-CIFRADA")
        wait_for(ea, lambda e: e.get("op") == "dm_ok" and e.get("ref") == 7)
        a.send({"op": "dm", "to": "NinguemAqui-0000", "blob": "x"})
        wait_for(ea, lambda e: e.get("op") == "error" and e.get("code") == "offline")
        print("OK: modo HTTP (login, sala, presenca, mensagem, mensagem direta, offline)")
    finally:
        a.stop()
        b.stop()
        srv.shutdown()


if __name__ == "__main__":
    main()
