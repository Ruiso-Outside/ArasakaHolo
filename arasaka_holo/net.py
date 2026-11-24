"""
ARASAKA HOLO // cliente de rede (asyncio + websockets).

Mantem a conexao com o servidor (reconecta sozinho), faz a autenticacao
(assinatura + prova de trabalho) e entrega eventos para quem chamou.
"""
from __future__ import annotations

import asyncio
import http.client
import json
import re
import socket
import ssl
import threading
import time
import urllib.request

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


class OldServer(Exception):
    """O relay nao prende a assinatura ao endereco (autenticacao v2)."""


async def in_thread(fn, *a):
    """Roda fn numa thread daemon. (O executor padrao do asyncio seguraria o fechamento do app ate o fim do poll.)"""
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    def put(ok, v):
        if not fut.done():
            fut.set_result(v) if ok else fut.set_exception(v)

    def run():
        try:
            r = (True, fn(*a))
        except Exception as e:  # noqa: BLE001
            r = (False, e)
        try:
            loop.call_soon_threadsafe(put, *r)
        except RuntimeError:        # o loop ja fechou: ninguem espera mais a resposta
            pass
    threading.Thread(target=run, daemon=True, name="holo-post").start()
    return await fut


def tls_context() -> ssl.SSLContext:
    """Certificados do sistema mais os do certifi: um Windows recem-instalado pode ainda nao ter a raiz do site."""
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except Exception:  # noqa: BLE001
        pass
    return ctx


_CTX: ssl.SSLContext | None = None


def _connect(addr, timeout=None, source_address=None, **_kw):
    """Tenta cada endereco do servidor por poucos segundos: um IPv6 quebrado nao pode travar tudo."""
    last: OSError | None = None
    for fam, kind, proto, _c, sa in socket.getaddrinfo(addr[0], addr[1], 0, socket.SOCK_STREAM):
        s = socket.socket(fam, kind, proto)
        try:
            s.settimeout(min(timeout, 5) if isinstance(timeout, (int, float)) else 5)
            s.connect(sa)
            s.settimeout(timeout if isinstance(timeout, (int, float)) else None)
            return s
        except OSError as e:
            s.close()
            last = e
    raise last or OSError("nenhum endereco")


class _HTTP(http.client.HTTPConnection):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._create_connection = _connect


class _HTTPS(http.client.HTTPSConnection):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._create_connection = _connect


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_HTTP, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_HTTPS, req, context=_CTX)


def request(url: str, data: dict, timeout: float) -> tuple[dict, str]:
    """POST JSON sincrono (roda numa thread): (resposta, cabecalho Date). Sem cookies e com um user-agent fixo, sem
    dados do sistema. O proxy do sistema e respeitado: ignorar poderia mostrar o IP de quem usa um de proposito."""
    global _CTX
    if _CTX is None:
        _CTX = tls_context()
    req = urllib.request.Request(url, data=json.dumps(data, separators=(",", ":")).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "ARASAKA-HOLO",
                                          "Accept": "application/json"})
    with urllib.request.build_opener(_HTTPHandler(), _HTTPSHandler()).open(req, timeout=timeout) as r:
        body, date = r.read(512 * 1024), r.headers.get("Date", "")
    try:
        return json.loads(body), date
    except ValueError:
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        raise NotHttpRelay(m.group(1).decode("utf-8", "replace").strip()[:80] if m else "sem JSON") from None


def _post(url: str, data: dict, timeout: float) -> dict:
    return request(url, data, timeout)[0]


def friendly_error(e: Exception) -> str:
    """Motivo da falha em portugues, para aparecer na tela (e nao so 'OFFLINE')."""
    name = type(e).__name__
    txt = str(e)
    if name == "HTTPError":
        code = getattr(e, "code", "")
        if code in (404, 405):
            return "esse endereco nao tem um servidor HOLO (HTTP %s): confira o caminho" % code
        if code in (403, 429, 503):
            return f"o servidor recusou a sua rede (HTTP {code}): protecao da hospedagem, VPN ou muitas tentativas"
        return f"o servidor respondeu HTTP {code}"
    if name == "URLError":
        return friendly_error(getattr(e, "reason", e)) if not isinstance(getattr(e, "reason", None), str) else str(e.reason)[:160]
    if name == "OldServer":
        return "servidor desatualizado: envie o index.php novo (pasta relay-php) ou atualize o arasaka-holo-server"
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
        return "sem resposta: servidor desligado, ou VPN, firewall ou antivirus bloqueando"
    if name == "gaierror" or "Name or service not known" in txt or "getaddrinfo" in txt:
        return "dominio nao encontrado (DNS)"
    if isinstance(e, ConnectionRefusedError) or "Connect call failed" in txt or "refused" in txt.lower():
        return "conexao recusada: endereco errado, proxy do sistema ou bloqueio na rede"
    if name == "SSLCertVerificationError" or "CERTIFICATE_VERIFY_FAILED" in txt:
        return "certificado TLS nao confere: acerte a data e a hora do sistema (ou o antivirus esta no meio)"
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
        self.unsent: list[dict] = []      # msg/dm que falharam no envio: vao de novo ao reconectar (quem recebe
                                          # ignora repetidas pelo id)

    # ------------------------------------------------------------ thread
    def start(self):
        self.thread = threading.Thread(target=self._thread, daemon=True, name="holo-net")
        self.thread.start()

    def _thread(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.queue = asyncio.Queue()
        try:
            while not self.stop_flag:
                try:
                    self.loop.run_until_complete(self._run())
                    break
                except Exception as e:  # noqa: BLE001      erro inesperado: mostra e tenta de novo, nunca morre calado
                    self.connected = False
                    self.on_event({"op": "_state", "state": "offline", "url": self.url,
                                   "error": f"{friendly_error(e)} [{type(e).__name__}]"})
                    time.sleep(5)
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
            for _ in range(int(delay * 5)):      # em fatias: parar nao espera o fim da pausa
                if self.stop_flag:
                    break
                await asyncio.sleep(0.2)
            delay = min(delay * 2, 30)
        self.on_event({"op": "_state", "state": "stopped"})

    def _auth(self, hello: dict, nonce: int) -> dict:
        ch = str(hello["challenge"])
        return {"op": "auth", "v": crypto.AUTH, "nick": self.ident.nick, "pk": self.ident.pk_b64, "pow": nonce,
                "sig": crypto.auth_signature(self.ident.sk, ch, self.ident.nick, crypto.url_host(self.url))}

    async def _solve(self, hello: dict) -> int:
        if hello.get("auth") != crypto.AUTH:
            raise OldServer()
        bits = int(hello.get("pow", 18))
        if not 0 <= bits <= 24:            # um servidor nao pode travar o seu processador
            raise ConnectionError("o servidor pediu uma prova de trabalho fora do normal")
        self.on_event({"op": "_state", "state": "login", "url": self.url})
        return await in_thread(crypto.solve_pow, str(hello["challenge"]), self.ident.nick, self.ident.pk_b64, bits)

    def _welcome(self, hello: dict, resp: dict) -> bool:
        """True = entrou. False = recusado de vez (nao adianta tentar de novo)."""
        if resp.get("op") == "error":
            self.on_event(resp)
            if resp.get("code") in ("nick_taken", "bad_auth"):
                self.stop_flag = True
                return False
            raise ConnectionError(resp.get("msg"))
        if resp.get("op") != "welcome":
            raise ConnectionError("resposta inesperada do servidor")
        self.connected = True
        resp["motd"] = hello.get("motd", "")
        self.on_event(resp)
        self.on_event({"op": "_state", "state": "online", "url": self.url})
        return True

    def _resume(self) -> list[dict]:
        """O que enviar logo apos conectar: entra nas salas de novo e reenvia o que falhou."""
        out = [{"op": "join", "room": rid} for rid in list(self.rooms)] + self.unsent
        self.unsent = []
        return out

    def _failed(self, msgs: list[dict]):
        self.unsent = (self.unsent + [m for m in msgs if m.get("op") in ("msg", "dm")])[-20:]

    # ------------------------------------------------------------ relay por HTTP (hospedagem PHP)
    async def _run_http(self):
        def post(data, timeout=15):
            return in_thread(_post, self.url, data, timeout)

        hello = await post({"op": "hello"})
        if not isinstance(hello, dict):
            raise NotHttpRelay()
        if hello.get("op") == "error":
            raise ConnectionError(hello.get("msg"))
        if hello.get("op") != "hello" or hello.get("transport") != "http":
            raise NotHttpRelay()
        auth = self._auth(hello, await self._solve(hello))
        resp = await post({**auth, "challenge": hello["challenge"]})
        token = resp.pop("token", "")
        if not self._welcome(hello, resp):
            return
        for m in self._resume():
            self.queue.put_nowait(m)

        def dispatch(r):
            if r.get("op") == "error" and r.get("code") == "session":
                raise SessionLost()
            for ev in r.get("events", []):
                if isinstance(ev, dict):
                    self.on_event(ev)

        async def poller():
            fails = 0
            while True:
                try:
                    r = await post({"op": "poll", "token": token}, 40)
                    fails = 0
                except OSError:                        # uma falha isolada nao derruba a sessao
                    fails += 1
                    if fails >= 3:
                        raise
                    await asyncio.sleep(fails)
                    continue
                dispatch(r)

        async def writer():
            while True:
                msg = await self.queue.get()
                if msg.get("op") == "__stop__":
                    try:
                        await asyncio.wait_for(post({"op": "bye", "token": token}, 3), 2.5)   # some da sala na hora
                    except Exception:  # noqa: BLE001
                        pass
                    return
                batch, size = [msg], len(str(msg))
                while not self.queue.empty() and len(batch) < 20 and size < 60000:
                    nxt = self.queue.get_nowait()
                    if nxt.get("op") == "__stop__":
                        self.queue.put_nowait(nxt)
                        break
                    batch.append(nxt)
                    size += len(str(nxt))
                try:
                    r = await post({"op": "send", "token": token, "msgs": batch})
                    if r.get("code") == "session":
                        self._failed(batch)
                except Exception:
                    self._failed(batch)
                    raise
                dispatch(r)

        tasks = [asyncio.create_task(poller()), asyncio.create_task(writer())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
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
                await ws.send(json.dumps(self._auth(hello, await self._solve(hello))))
                resp = json.loads(await asyncio.wait_for(ws.recv(), 15))
                if not self._welcome(hello, resp):
                    return
                for m in self._resume():
                    self.queue.put_nowait(m)
                await self._pump(ws)
        except Exception as e:  # noqa: BLE001
            if not self.stop_flag:
                self.on_event({"op": "_state", "state": "offline", "error": friendly_error(e), "url": self.url})

    async def _pump(self, ws):
        async def reader():
            async for raw in ws:
                try:
                    m = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(m, dict):
                    self.on_event(m)

        async def writer():
            while True:
                msg = await self.queue.get()
                if msg.get("op") == "__stop__":
                    await ws.close()
                    return
                try:
                    await ws.send(json.dumps(msg, separators=(",", ":")))
                except Exception:
                    self._failed([msg])
                    raise

        async def pinger():
            while True:
                await asyncio.sleep(15)
                await ws.send(json.dumps({"op": "ping", "t": time.time()}))

        tasks = [asyncio.create_task(reader()), asyncio.create_task(writer()), asyncio.create_task(pinger())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for t in done:
            if t.exception():
                raise t.exception()
