"""
ARASAKA HOLO // servidor relay "cego".

    python -m arasaka_holo.server [--host 0.0.0.0] [--port 7077] [--data PASTA] [--cert c.pem --key k.pem]

O que o servidor guarda em disco: somente  nick -> chave publica  (e o mes do registro).
O que fica so na memoria: conexoes abertas e quais ids de sala cada uma ouve.
O que ele NUNCA ve nem guarda: conteudo das mensagens (cifradas no cliente), nomes ou senhas das
salas (so um hash), enderecos IP (nao registrados), MAC (nunca sai do cliente), historico (nada e
armazenado: quem estava offline nao recebe).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import secrets
import ssl
import time
from pathlib import Path

from .crypto import POW_BITS, PROTO, check_auth, pow_ok
from .identity import NICK_RE

MAX_FRAME = 32 * 1024
MAX_ROOMS = 64
RATE_N, RATE_WINDOW = 30, 10.0       # 30 mensagens / 10 s por conexao

logging.getLogger("websockets").setLevel(logging.ERROR)   # nao registra conexoes / IPs


class Directory:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, dict] = {}
        try:
            self.data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass

    def get(self, nick: str) -> str | None:
        e = self.data.get(nick)
        return e["pk"] if e else None

    def register(self, nick: str, pk: str):
        self.data[nick] = {"pk": pk, "since": time.strftime("%Y-%m")}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
        tmp.replace(self.path)


class Conn:
    __slots__ = ("ws", "nick", "pk", "rooms", "times")

    def __init__(self, ws):
        self.ws = ws
        self.nick = ""
        self.pk = ""
        self.rooms: set[str] = set()
        self.times: list[float] = []

    def rate_ok(self) -> bool:
        now = time.monotonic()
        self.times = [t for t in self.times if now - t < RATE_WINDOW]
        if len(self.times) >= RATE_N:
            return False
        self.times.append(now)
        return True


class HoloServer:
    def __init__(self, data_dir: Path, motd: str = ""):
        self.dir = Directory(Path(data_dir) / "directory.json")
        self.conns: set[Conn] = set()
        self.by_nick: dict[str, set[Conn]] = {}
        self.rooms: dict[str, set[Conn]] = {}
        self.motd = motd
        self.started = time.time()

    async def send(self, c: Conn, msg: dict):
        try:
            await c.ws.send(json.dumps(msg, separators=(",", ":")))
        except Exception:
            pass

    def members(self, rid: str) -> list[str]:
        return sorted({c.nick for c in self.rooms.get(rid, ())})

    async def broadcast_presence(self, rid: str, nick: str, on: bool, skip: Conn | None = None):
        for o in list(self.rooms.get(rid, ())):
            if o is not skip:
                await self.send(o, {"op": "presence", "room": rid, "nick": nick, "on": on,
                                    "count": len(self.rooms.get(rid, ()))})

    async def handler(self, ws):
        c = Conn(ws)
        challenge = secrets.token_hex(16)
        await self.send(c, {"op": "hello", "proto": PROTO, "challenge": challenge, "pow": POW_BITS,
                            "motd": self.motd})
        try:
            # ---------------------------------------------------- autenticacao
            raw = await asyncio.wait_for(ws.recv(), timeout=60)
            m = json.loads(raw)
            nick, pk = str(m.get("nick", "")), str(m.get("pk", ""))
            if m.get("op") != "auth" or not NICK_RE.match(nick) or len(pk) > 64:
                return await self.send(c, {"op": "error", "code": "bad_auth", "msg": "autenticacao invalida"})
            known = self.dir.get(nick)
            if known and known != pk:
                return await self.send(c, {"op": "error", "code": "nick_taken",
                                           "msg": "este nick ja pertence a outra chave"})
            if not check_auth(pk, challenge, nick, str(m.get("sig", ""))):
                return await self.send(c, {"op": "error", "code": "bad_sig", "msg": "assinatura invalida"})
            new = not known
            if new:
                if not pow_ok(challenge, nick, pk, int(m.get("pow", -1))):
                    return await self.send(c, {"op": "error", "code": "pow", "msg": "prova de trabalho invalida"})
                self.dir.register(nick, pk)
            c.nick, c.pk = nick, pk
            self.conns.add(c)
            self.by_nick.setdefault(nick, set()).add(c)
            await self.send(c, {"op": "welcome", "nick": nick, "new": new, "online": len(self.by_nick)})

            # ---------------------------------------------------- mensagens
            async for raw in ws:
                if len(raw) > MAX_FRAME:
                    await self.send(c, {"op": "error", "code": "too_big", "msg": "mensagem grande demais"})
                    continue
                try:
                    m = json.loads(raw)
                except ValueError:
                    continue
                op = m.get("op")
                if op in ("msg", "dm") and not c.rate_ok():
                    await self.send(c, {"op": "error", "code": "rate", "msg": "devagar: limite de mensagens"})
                    continue
                if op == "join":
                    rid = str(m.get("room", ""))[:64]
                    if not rid or len(c.rooms) >= MAX_ROOMS:
                        continue
                    c.rooms.add(rid)
                    self.rooms.setdefault(rid, set()).add(c)
                    await self.send(c, {"op": "joined", "room": rid, "members": self.members(rid)})
                    await self.broadcast_presence(rid, c.nick, True, skip=c)
                elif op == "leave":
                    rid = str(m.get("room", ""))
                    await self._leave(c, rid)
                elif op == "msg":
                    rid = str(m.get("room", ""))
                    if rid not in c.rooms:
                        continue
                    out = {"op": "msg", "room": rid, "blob": str(m.get("blob", ""))}
                    for o in list(self.rooms.get(rid, ())):
                        await self.send(o, out)
                elif op == "dm":
                    to = str(m.get("to", ""))
                    targets = self.by_nick.get(to)
                    if not targets:
                        await self.send(c, {"op": "error", "code": "offline", "to": to,
                                            "msg": f"{to} esta offline (nada e guardado no servidor)"})
                        continue
                    out = {"op": "dm", "from": c.nick, "from_pk": c.pk, "blob": str(m.get("blob", ""))}
                    for o in list(targets):
                        await self.send(o, out)
                    await self.send(c, {"op": "dm_ok", "to": to, "ref": m.get("ref")})
                elif op == "whois":
                    n = str(m.get("nick", ""))
                    await self.send(c, {"op": "whois", "nick": n, "pk": self.dir.get(n),
                                        "online": n in self.by_nick})
                elif op == "ping":
                    await self.send(c, {"op": "pong", "t": m.get("t")})
        except (asyncio.TimeoutError, ValueError):
            pass
        except Exception:
            pass
        finally:
            for rid in list(c.rooms):
                await self._leave(c, rid)
            self.conns.discard(c)
            if c.nick and c.nick in self.by_nick:
                self.by_nick[c.nick].discard(c)
                if not self.by_nick[c.nick]:
                    del self.by_nick[c.nick]

    async def _leave(self, c: Conn, rid: str):
        if rid in c.rooms:
            c.rooms.discard(rid)
            s = self.rooms.get(rid)
            if s:
                s.discard(c)
                if not s:
                    del self.rooms[rid]
            if not any(o.nick == c.nick for o in self.rooms.get(rid, ())):
                await self.broadcast_presence(rid, c.nick, False)

    async def stats_loop(self, quiet: bool):
        while True:
            await asyncio.sleep(60)
            if not quiet:
                print(f"[HOLO] {len(self.conns)} conexoes · {len(self.by_nick)} nicks online · "
                      f"{len(self.rooms)} salas ativas · {len(self.dir.data)} nicks registrados", flush=True)


async def serve(host: str, port: int, data_dir: Path, cert: str = "", key: str = "", motd: str = "",
                quiet: bool = False, stop: asyncio.Event | None = None, ready=None):
    from websockets.asyncio.server import serve as ws_serve
    srv = HoloServer(data_dir, motd)
    ctx = None
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
    async with ws_serve(srv.handler, host, port, ssl=ctx, max_size=MAX_FRAME * 2, ping_interval=25,
                        ping_timeout=20, server_header=None):
        if not quiet:
            scheme = "wss" if ctx else "ws"
            print(f"[HOLO] servidor cego em {scheme}://{host}:{port}  ·  dados: {data_dir}", flush=True)
        if ready:
            ready()
        task = asyncio.create_task(srv.stats_loop(quiet))
        try:
            if stop is None:
                await asyncio.Future()
            else:
                await stop.wait()
        finally:
            task.cancel()


def default_data_dir() -> Path:
    from .identity import config_dir
    return config_dir() / "server"


def main():
    ap = argparse.ArgumentParser(description="ARASAKA HOLO // servidor relay sem logs")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=7077)
    ap.add_argument("--data", default=str(default_data_dir()), help="pasta do diretorio de nicks")
    ap.add_argument("--cert", default="", help="certificado TLS (para wss://)")
    ap.add_argument("--key", default="", help="chave privada TLS")
    ap.add_argument("--motd", default="", help="mensagem de boas-vindas")
    a = ap.parse_args()
    try:
        asyncio.run(serve(a.host, a.port, Path(a.data), a.cert, a.key, a.motd))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    main()
