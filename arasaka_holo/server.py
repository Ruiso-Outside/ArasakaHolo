"""
ARASAKA HOLO // servidor relay "cego".

    python -m arasaka_holo.server [--host 0.0.0.0] [--port 7077] [--data PASTA] [--cert c.pem --key k.pem]
                                  [--stun stun:host:porta] [--turn turn:host:3478 --turn-secret SEGREDO]

O que o servidor guarda em disco: somente  nick -> chave publica  (e o mes do registro).
O que fica so na memoria: conexoes abertas e quais ids de sala cada uma ouve.
O que ele NUNCA ve nem guarda: conteudo das mensagens (cifradas no cliente), nomes ou senhas das
salas (so um hash), enderecos IP (nao registrados), MAC (nunca sai do cliente), historico (nada e
armazenado: quem estava offline nao recebe).
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import ssl
import time
from pathlib import Path

from .crypto import AUTH, POW_BITS, PROTO, check_auth, host_id, pow_ok
from .identity import valid_nick

MAX_FRAME = 32 * 1024
MAX_ROOMS = 64
MAX_PER_NICK = 8                     # conexoes simultaneas do mesmo nick
SEND_TIMEOUT = 10                    # s: um cliente travado nao pode segurar a sala inteira
OPS_N = 120                          # operacoes de qualquer tipo / 10 s por conexao
DEFAULT_STUN = "stun:stun.cloudflare.com:3478"
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


def ice_servers(stun: str = DEFAULT_STUN, turn: str = "", secret: str = "", user: str = "", password: str = "",
                ttl: int = 86400) -> list[dict]:
    """Servidores que os clientes usam nas calls. Com 'secret' (use-auth-secret do coturn) a credencial expira."""
    out = [{"urls": [stun]}] if stun else []
    if turn:
        if secret:
            user = f"{int(time.time()) + ttl}:holo"
            password = base64.b64encode(hmac.new(secret.encode(), user.encode(), hashlib.sha1).digest()).decode()
        out.append({"urls": [turn], "username": user, "credential": password})
    return out


class Conn:
    __slots__ = ("ws", "nick", "pk", "rooms", "times", "ops")

    def __init__(self, ws):
        self.ws = ws
        self.nick = ""
        self.pk = ""
        self.rooms: set[str] = set()
        self.times: list[float] = []
        self.ops: list[float] = []

    @staticmethod
    def _hit(times: list[float], n: int) -> bool:
        now = time.monotonic()
        times[:] = [t for t in times if now - t < RATE_WINDOW]
        if len(times) >= n:
            return False
        times.append(now)
        return True

    def rate_ok(self) -> bool:
        return self._hit(self.times, RATE_N)

    def ops_ok(self) -> bool:
        return self._hit(self.ops, OPS_N)


class HoloServer:
    def __init__(self, data_dir: Path, motd: str = "", ice=None, public_host: str = "", legacy: bool = True):
        self.dir = Directory(Path(data_dir) / "directory.json")
        self.conns: set[Conn] = set()
        self.by_nick: dict[str, set[Conn]] = {}
        self.rooms: dict[str, set[Conn]] = {}
        self.motd = motd
        self.ice = ice or ice_servers
        self.public_host = public_host      # atras de proxy que troca o cabecalho Host
        self.legacy = legacy                # aceita login do HOLO 1.1 (sem o endereco na assinatura)

    async def send(self, c: Conn, msg: dict):
        try:
            await asyncio.wait_for(c.ws.send(json.dumps(msg, separators=(",", ":"))), SEND_TIMEOUT)
        except asyncio.TimeoutError:
            c.ws.transport.abort()
        except Exception:
            pass

    async def send_all(self, conns, msg: dict):
        await asyncio.gather(*(self.send(c, msg) for c in list(conns)))

    def members(self, rid: str) -> list[str]:
        return sorted({c.nick for c in self.rooms.get(rid, ())})

    async def broadcast_presence(self, rid: str, nick: str, on: bool, skip: Conn | None = None):
        members = self.rooms.get(rid, set())
        await self.send_all([o for o in members if o is not skip],
                            {"op": "presence", "room": rid, "nick": nick, "on": on, "count": len(members)})

    async def handler(self, ws):
        c = Conn(ws)
        challenge = secrets.token_hex(16)
        await self.send(c, {"op": "hello", "proto": PROTO, "challenge": challenge, "pow": POW_BITS,
                            "motd": self.motd, "auth": AUTH})
        try:
            # ---------------------------------------------------- autenticacao
            raw = await asyncio.wait_for(ws.recv(), timeout=60)
            m = json.loads(raw)
            nick, pk = str(m.get("nick", "")), str(m.get("pk", ""))
            if m.get("op") != "auth" or not valid_nick(nick) or len(pk) > 64:
                return await self.send(c, {"op": "error", "code": "bad_auth", "msg": "autenticacao invalida"})
            known = self.dir.get(nick)
            if known and known != pk:
                return await self.send(c, {"op": "error", "code": "nick_taken",
                                           "msg": "este nick ja pertence a outra chave"})
            host = host_id(self.public_host or ws.request.headers.get("Host", ""))
            if not check_auth(pk, challenge, nick, str(m.get("sig", "")), host, self.legacy):
                return await self.send(c, {"op": "error", "code": "bad_sig", "msg": "assinatura invalida (se o "
                                           "servidor esta atras de um proxy, use --public-host)"})
            if len(self.by_nick.get(nick, ())) >= MAX_PER_NICK:
                return await self.send(c, {"op": "error", "code": "too_many", "msg": "conexoes demais deste nick"})
            new = not known
            if new:
                if not pow_ok(challenge, nick, pk, int(m.get("pow", -1))):
                    return await self.send(c, {"op": "error", "code": "pow", "msg": "prova de trabalho invalida"})
                self.dir.register(nick, pk)
            c.nick, c.pk = nick, pk
            self.conns.add(c)
            self.by_nick.setdefault(nick, set()).add(c)
            await self.send(c, {"op": "welcome", "nick": nick, "new": new, "online": len(self.by_nick),
                                "ice": self.ice()})

            # ---------------------------------------------------- mensagens
            async for raw in ws:
                if len(raw) > MAX_FRAME:
                    await self.send(c, {"op": "error", "code": "too_big", "msg": "mensagem grande demais"})
                    continue
                try:
                    m = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(m, dict):
                    continue
                if not c.ops_ok():
                    await self.send(c, {"op": "error", "code": "rate", "msg": "devagar: limite de operacoes"})
                    continue
                op = m.get("op")
                if op in ("msg", "dm") and not c.rate_ok():
                    await self.send(c, {"op": "error", "code": "rate", "msg": "devagar: limite de mensagens"})
                    continue
                if op == "join":
                    rid = str(m.get("room", ""))[:64]
                    if not rid or (rid not in c.rooms and len(c.rooms) >= MAX_ROOMS):
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
                    await self.send_all(self.rooms.get(rid, ()), out)
                elif op == "dm":
                    to = str(m.get("to", ""))
                    targets = self.by_nick.get(to)
                    if not targets:
                        await self.send(c, {"op": "error", "code": "offline", "to": to,
                                            "msg": f"{to} esta offline (nada e guardado no servidor)"})
                        continue
                    out = {"op": "dm", "from": c.nick, "from_pk": c.pk, "blob": str(m.get("blob", ""))}
                    await self.send_all(targets, out)
                    await self.send(c, {"op": "dm_ok", "to": to, "ref": m.get("ref")})
                elif op == "whois":
                    n = str(m.get("nick", ""))
                    await self.send(c, {"op": "whois", "nick": n, "pk": self.dir.get(n),
                                        "online": n in self.by_nick})
                elif op == "ice":
                    await self.send(c, {"op": "ice", "servers": self.ice()})
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
                quiet: bool = False, stop: asyncio.Event | None = None, ready=None, ice=None, public_host: str = "",
                legacy: bool = True):
    from websockets.asyncio.server import serve as ws_serve
    srv = HoloServer(data_dir, motd, ice, public_host, legacy)
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
    ap.add_argument("--public-host", default="", help="endereco que os clientes usam (ex.: chat.exemplo.com), se um "
                                                      "proxy reverso trocar o cabecalho Host")
    ap.add_argument("--no-legacy", action="store_true", help="recusa clientes anteriores ao HOLO 1.2")
    ap.add_argument("--stun", default=DEFAULT_STUN, help="servidor STUN das calls ('' desliga)")
    ap.add_argument("--turn", default="", help="servidor TURN das calls (ex.: turn:exemplo.com:3478?transport=udp)")
    ap.add_argument("--turn-secret", default=os.environ.get("HOLO_TURN_SECRET", ""),
                    help="static-auth-secret do coturn (ou a variavel HOLO_TURN_SECRET)")
    ap.add_argument("--turn-user", default="")
    ap.add_argument("--turn-pass", default=os.environ.get("HOLO_TURN_PASS", ""))
    a = ap.parse_args()
    try:
        asyncio.run(serve(a.host, a.port, Path(a.data), a.cert, a.key, a.motd, public_host=a.public_host,
                          legacy=not a.no_legacy,
                          ice=lambda: ice_servers(a.stun, a.turn, a.turn_secret, a.turn_user, a.turn_pass)))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    main()
