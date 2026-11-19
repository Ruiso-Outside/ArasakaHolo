"""
ARASAKA HOLO // cliente de rede (asyncio + websockets).

Mantem a conexao com o servidor (reconecta sozinho), faz a autenticacao
(assinatura + prova de trabalho) e entrega eventos para quem chamou.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time

from . import crypto
from .identity import Identity


def normalize_url(url: str) -> str:
    """Aceita o link como a pessoa colou. https:// e http:// ficam (o cliente tenta o relay por HTTP e, se nao
    for um, o WebSocket no mesmo endereco); sem esquema vira ws://."""
    u = (url or "").strip()
    if u and "://" not in u:
        return "ws://" + u
    return u


def ws_url(url: str) -> str:
    """Endereco WebSocket equivalente: https:// vira wss:// e http:// vira ws://."""
    low = url.lower()
    if low.startswith("https://"):
        return "wss://" + url[8:]
    if low.startswith("http://"):
        return "ws://" + url[7:]
    return url


class NotHttpRelay(Exception):
    """O endereco http(s) nao e um relay HOLO por HTTP: tenta o WebSocket."""


class SessionLost(Exception):
    pass


def _post(url: str, data: dict, timeout: float) -> dict:
    """POST JSON sincrono (roda numa thread). Sem cookies e com um user-agent fixo, sem dados do sistema."""
    import urllib.request
    req = urllib.request.Request(url, data=json.dumps(data, separators=(",", ":")).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "ARASAKA-HOLO",
                                          "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read(512 * 1024)
    try:
        return json.loads(body)
    except ValueError:
        raise NotHttpRelay() from None


def friendly_error(e: Exception) -> str:
    """Motivo da falha em portugues, para aparecer na tela (e nao so 'OFFLINE')."""
    name = type(e).__name__
    txt = str(e)
    if name == "HTTPError":
        code = getattr(e, "code", "")
        if code in (404, 405):
            return "esse endereco nao tem um servidor HOLO (HTTP %s): confira o caminho" % code
        return f"o servidor respondeu HTTP {code}"
    if name == "URLError":
        return friendly_error(getattr(e, "reason", e)) if not isinstance(getattr(e, "reason", None), str) else str(e.reason)[:160]
    if name == "NotHttpRelay":
        return "esse endereco e um site, nao um servidor HOLO"
    if name == "InvalidURI":
        return "endereco invalido: use ws://ip:7077 ou wss://dominio"
    if name == "InvalidStatus":
        code = getattr(getattr(e, "response", None), "status_code", "")
        if code == 404:
            return "esse endereco nao tem um servidor HOLO (HTTP 404): confira o caminho"
        return f"esse endereco e um site, nao um servidor HOLO (HTTP {code})"
    if name in ("TimeoutError", "CancelledError") or "timed out" in txt:
        return "sem resposta: servidor desligado ou porta bloqueada no firewall/roteador"
    if name == "gaierror" or "Name or service not known" in txt or "getaddrinfo" in txt:
        return "dominio nao encontrado (DNS)"
    if isinstance(e, ConnectionRefusedError) or "Connect call failed" in txt or "refused" in txt.lower():
        return "conexao recusada: nao ha servidor HOLO rodando nessa porta"
    if name == "SSLCertVerificationError" or "CERTIFICATE_VERIFY_FAILED" in txt:
        return "certificado TLS invalido no servidor (wss)"
    if "SSL" in name or "WRONG_VERSION_NUMBER" in txt:
        return "o servidor nao usa TLS nessa porta: troque wss:// por ws://"
    return (txt or name)[:160]


class HoloClient:
    def __init__(self, url: str, ident: Identity, on_event, proxy: str | None = None):
        self.url = normalize_url(url)
        self.ident = ident
        self.on_event = on_event          # chamado na thread da rede com dicts
        self.proxy = proxy
        self.loop: asyncio.AbstractEventLoop | None = None
        self.queue: asyncio.Queue | None = None
        self.stop_flag = False
        self.connected = False
        self.rooms: set[str] = set()      # salas para re-entrar apos reconectar
        self.thread: threading.Thread | None = None

    # ------------------------------------------------------------ thread
    def start(self):
        self.thread = threading.Thread(target=self._thread, daemon=True, name="holo-net")
        self.thread.start()

    def _thread(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.queue = asyncio.Queue()
        try:
            self.loop.run_until_complete(self._run())
        finally:
            self.loop.close()

    def send(self, msg: dict):
        if msg.get("op") == "join":
            self.rooms.add(msg["room"])
        elif msg.get("op") == "leave":
            self.rooms.discard(msg["room"])
        if self.loop and self.queue:
            self.loop.call_soon_threadsafe(self.queue.put_nowait, msg)

    def stop(self):
        self.stop_flag = True
        if self.loop and self.queue and not self.loop.is_closed():
            try:
                self.loop.call_soon_threadsafe(self.queue.put_nowait, {"op": "__stop__"})
            except RuntimeError:
                pass
        if self.thread:
            self.thread.join(timeout=3)

    # ------------------------------------------------------------ conexao
    async def _run(self):
        delay = 1.0
        while not self.stop_flag:
            self.on_event({"op": "_state", "state": "connecting", "url": self.url})
            if self.url.lower().startswith(("http://", "https://")):
                try:
                    await self._run_http()
                    delay = 1.0
                except NotHttpRelay:
                    await self._run_ws(ws_url(self.url))     # site com WebSocket (proxy reverso)
                except SessionLost:
                    delay = 1.0
                except Exception as e:  # noqa: BLE001
                    if not self.stop_flag:
                        self.on_event({"op": "_state", "state": "offline", "error": friendly_error(e), "url": self.url})
            else:
                await self._run_ws(self.url)
            self.connected = False
            if self.stop_flag:
                break
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)
        self.on_event({"op": "_state", "state": "stopped"})

    # ------------------------------------------------------------ relay por HTTP (hospedagem PHP)
    async def _run_http(self):
        loop = asyncio.get_running_loop()
        post = lambda data, timeout=15: loop.run_in_executor(None, _post, self.url, data, timeout)  # noqa: E731
        hello = await post({"op": "hello"})
        if hello.get("op") != "hello" or hello.get("transport") != "http":
            raise NotHttpRelay()
        ch = hello["challenge"]
        nonce = await loop.run_in_executor(None, crypto.solve_pow, ch, self.ident.nick, self.ident.pk_b64,
                                           int(hello.get("pow", 18)))
        resp = await post({"op": "auth", "challenge": ch, "nick": self.ident.nick, "pk": self.ident.pk_b64,
                           "sig": crypto.auth_signature(self.ident.sk, ch, self.ident.nick), "pow": nonce})
        if resp.get("op") == "error":
            self.on_event(resp)
            if resp.get("code") in ("nick_taken", "bad_auth"):
                self.stop_flag = True
                return
            raise ConnectionError(resp.get("msg"))
        token = resp.pop("token")
        self.connected = True
        resp["motd"] = hello.get("motd", "")
        self.on_event(resp)
        self.on_event({"op": "_state", "state": "online", "url": self.url})
        for rid in list(self.rooms):
            self.queue.put_nowait({"op": "join", "room": rid})

        def dispatch(r):
            if r.get("op") == "error" and r.get("code") == "session":
                raise SessionLost()
            for ev in r.get("events", []):
                self.on_event(ev)

        async def poller():
            while True:
                dispatch(await post({"op": "poll", "token": token}, timeout=40))

        async def writer():
            while True:
                msg = await self.queue.get()
                if msg.get("op") == "__stop__":
                    return
                batch = [msg]
                while not self.queue.empty() and len(batch) < 20:
                    nxt = self.queue.get_nowait()
                    if nxt.get("op") == "__stop__":
                        self.queue.put_nowait(nxt)
                        break
                    batch.append(nxt)
                dispatch(await post({"op": "send", "token": token, "msgs": batch}))

        tasks = [asyncio.create_task(poller()), asyncio.create_task(writer())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for t in done:
            if t.exception():
                raise t.exception()

    # ------------------------------------------------------------ WebSocket (servidor em Python)
    async def _run_ws(self, url: str):
        from websockets.asyncio.client import connect
        try:
            kw = {"max_size": 64 * 1024, "open_timeout": 10, "ping_interval": 20, "ping_timeout": 20,
                  "user_agent_header": None}
            if self.proxy:
                kw["proxy"] = self.proxy
            async with connect(url, **kw) as ws:
                hello = json.loads(await asyncio.wait_for(ws.recv(), 15))
                if hello.get("op") != "hello":
                    raise ConnectionError("servidor nao e um HOLO")
                ch = hello["challenge"]
                nonce = await asyncio.get_running_loop().run_in_executor(
                    None, crypto.solve_pow, ch, self.ident.nick, self.ident.pk_b64, int(hello.get("pow", 18)))
                await ws.send(json.dumps({"op": "auth", "nick": self.ident.nick, "pk": self.ident.pk_b64,
                                          "sig": crypto.auth_signature(self.ident.sk, ch, self.ident.nick),
                                          "pow": nonce}))
                resp = json.loads(await asyncio.wait_for(ws.recv(), 15))
                if resp.get("op") == "error":
                    self.on_event(resp)
                    if resp.get("code") in ("nick_taken", "bad_auth"):
                        self.stop_flag = True
                        return
                    raise ConnectionError(resp.get("msg"))
                self.connected = True
                resp["motd"] = hello.get("motd", "")
                self.on_event(resp)
                self.on_event({"op": "_state", "state": "online", "url": self.url})
                for rid in list(self.rooms):
                    await ws.send(json.dumps({"op": "join", "room": rid}))
                await self._pump(ws)
        except Exception as e:  # noqa: BLE001
            if not self.stop_flag:
                self.on_event({"op": "_state", "state": "offline", "error": friendly_error(e), "url": self.url})

    async def _pump(self, ws):
        async def reader():
            async for raw in ws:
                try:
                    self.on_event(json.loads(raw))
                except ValueError:
                    pass

        async def writer():
            while True:
                msg = await self.queue.get()
                if msg.get("op") == "__stop__":
                    await ws.close()
                    return
                await ws.send(json.dumps(msg, separators=(",", ":")))

        async def pinger():
            while True:
                await asyncio.sleep(15)
                await ws.send(json.dumps({"op": "ping", "t": time.time()}))

        tasks = [asyncio.create_task(reader()), asyncio.create_task(writer()), asyncio.create_task(pinger())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for t in done:
            if t.exception():
                raise t.exception()
