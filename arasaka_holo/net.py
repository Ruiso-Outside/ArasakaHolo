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


class HoloClient:
    def __init__(self, url: str, ident: Identity, on_event, proxy: str | None = None):
        self.url = url
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
        from websockets.asyncio.client import connect
        delay = 1.0
        while not self.stop_flag:
            self.on_event({"op": "_state", "state": "connecting", "url": self.url})
            try:
                kw = {"max_size": 64 * 1024, "open_timeout": 10, "ping_interval": 20, "ping_timeout": 20,
                      "user_agent_header": None}
                if self.proxy:
                    kw["proxy"] = self.proxy
                async with connect(self.url, **kw) as ws:
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
                            break
                        raise ConnectionError(resp.get("msg"))
                    self.connected = True
                    delay = 1.0
                    resp["motd"] = hello.get("motd", "")
                    self.on_event(resp)
                    self.on_event({"op": "_state", "state": "online", "url": self.url})
                    for rid in list(self.rooms):
                        await ws.send(json.dumps({"op": "join", "room": rid}))
                    await self._pump(ws)
            except Exception as e:  # noqa: BLE001
                if self.stop_flag:
                    break
                self.on_event({"op": "_state", "state": "offline", "error": str(e)[:160]})
            self.connected = False
            if self.stop_flag:
                break
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)
        self.on_event({"op": "_state", "state": "stopped"})

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
