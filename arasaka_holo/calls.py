"""
ARASAKA HOLO // calls de voz e compartilhamento de tela (WebRTC, par a par).

O audio e a tela vao direto de um PC para o outro, cifrados por DTLS-SRTP. A sinalizacao (oferta e resposta, com a
impressao digital DTLS) viaja como mensagem direta do HOLO: cifrada e assinada, entao o relay nao consegue entrar
no meio da call. Em sala, cada par de participantes tem a propria conexao (malha).

Nada e gravado. O relay nao carrega audio nem video: ele so informa os servidores STUN/TURN, usados para os dois
PCs se acharem atras dos roteadores.

As dependencias (aiortc, sounddevice, mss, numpy) sao opcionais: sem elas o chat funciona e a call fica desligada.
"""
from __future__ import annotations

import asyncio
import fractions
import json
import sys
import threading
import time
from collections import deque

try:
    import av
    import numpy as np
    from aiortc import (RTCBundlePolicy, RTCConfiguration, RTCIceServer, RTCIceTransportPolicy, RTCPeerConnection,
                        RTCRtpSender, RTCSessionDescription)
    from aiortc.codecs import vpx
    from aiortc.mediastreams import MediaStreamError, MediaStreamTrack
    MISSING = ""
    # tela precisa de mais banda que uma webcam (o padrao do aiortc e 0,5 a 1,5 Mbit/s)
    vpx.DEFAULT_BITRATE, vpx.MIN_BITRATE, vpx.MAX_BITRATE = 1_500_000, 300_000, 5_000_000
except Exception as _e:  # noqa: BLE001
    MISSING = f"{type(_e).__name__}: {_e}"
    MediaStreamTrack = object          # type: ignore[assignment,misc]

RATE = 48000
SAMPLES = 960                # 20 ms
MAX_PEERS = 6                # em malha, cada pessoa a mais custa uma conexao inteira
CONNECT_TIMEOUT = 30
AUDIO_TB = fractions.Fraction(1, RATE)
VIDEO_TB = fractions.Fraction(1, 90000)
PRESETS = {"texto": ("Texto nitido (1080p, 8 quadros/s)", 1920, 1080, 8),
           "equilibrado": ("Equilibrado (720p, 15 quadros/s)", 1280, 720, 15),
           "fluido": ("Fluido (720p, 24 quadros/s)", 1280, 720, 24)}


def available() -> bool:
    return not MISSING


# ================================================================ audio
def _hostapi():
    """(indice, e_wasapi): no Windows prefere WASAPI (menos atraso que MME)."""
    import sounddevice as sd
    if sys.platform == "win32":
        for i, h in enumerate(sd.query_hostapis()):
            if "WASAPI" in h["name"]:
                return i, True
    return sd.default.hostapi, False


def audio_devices() -> tuple[list[str], list[str]]:
    """(microfones, saidas) pelo nome."""
    try:
        import sounddevice as sd
        api, _w = _hostapi()
        devs = [d for d in sd.query_devices() if d["hostapi"] == api]
        return ([d["name"] for d in devs if d["max_input_channels"] > 0],
                [d["name"] for d in devs if d["max_output_channels"] > 0])
    except Exception:  # noqa: BLE001
        return [], []


class SoundDevice:
    """Microfone e alto-falante reais (PortAudio)."""

    def __init__(self, mic: str = "", speaker: str = ""):
        self.mic_name, self.spk_name = mic, speaker
        self.ins = self.outs = None

    def _pick(self, name: str, kind: str) -> dict:
        import sounddevice as sd
        api, wasapi = _hostapi()
        ch = "max_input_channels" if kind == "input" else "max_output_channels"
        dev = None
        for i, d in enumerate(sd.query_devices()):
            if d["hostapi"] == api and d["name"] == name and d[ch] > 0:
                dev = i
        if dev is None:
            dev = sd.query_hostapis(api)[f"default_{kind}_device"]
            dev = None if dev < 0 else dev
        kw = {"device": dev, "samplerate": RATE, "blocksize": SAMPLES, "channels": 1, "dtype": "int16",
              "latency": "low"}
        if wasapi:
            kw["extra_settings"] = sd.WasapiSettings(auto_convert=True)
        return kw

    def start(self, on_mic, fill) -> list[str]:
        """on_mic(bytes de 20 ms) e fill(n) -> bytes. Devolve os avisos (dispositivo que nao abriu)."""
        import sounddevice as sd
        warns = []

        def mic_cb(data, _frames, _t, _st):
            on_mic(bytes(data))

        def spk_cb(out, frames, _t, _st):
            out[:] = fill(frames)

        def try_open(cls, name, kind, cb):
            last = None
            for attempt in (lambda: self._pick(name, kind),
                            lambda: {"samplerate": RATE, "blocksize": SAMPLES, "channels": 1, "dtype": "int16"}):
                try:
                    s = cls(callback=cb, **attempt())
                    s.start()
                    return s
                except Exception as e:  # noqa: BLE001
                    last = e
            raise last

        try:
            self.ins = try_open(sd.RawInputStream, self.mic_name, "input", mic_cb)
        except Exception as e:  # noqa: BLE001
            warns.append(f"sem microfone ({str(e)[:80]}): voce so ouve")
        try:
            self.outs = try_open(sd.RawOutputStream, self.spk_name, "output", spk_cb)
        except Exception as e:  # noqa: BLE001
            warns.append(f"sem saida de audio ({str(e)[:80]})")
        return warns

    def stop(self):
        for s in (self.ins, self.outs):
            try:
                if s:
                    s.abort()
                    s.close()
            except Exception:  # noqa: BLE001
                pass
        self.ins = self.outs = None


class Mixer:
    """Soma o audio de todos os participantes para o alto-falante."""
    MAX = RATE // 4            # no maximo 250 ms guardados por pessoa (evita acumular atraso)

    def __init__(self):
        self.lock = threading.Lock()
        self.buf: dict[str, deque] = {}
        self.size: dict[str, int] = {}
        self.ready: dict[str, bool] = {}

    def add(self, nick: str, pcm):
        with self.lock:
            q = self.buf.setdefault(nick, deque())
            q.append(pcm)
            self.size[nick] = self.size.get(nick, 0) + len(pcm)
            while self.size[nick] > self.MAX and len(q) > 1:
                self.size[nick] -= len(q.popleft())

    def remove(self, nick: str):
        with self.lock:
            for d in (self.buf, self.size, self.ready):
                d.pop(nick, None)

    def fill(self, n: int) -> bytes:
        out = np.zeros(n, dtype=np.int32)
        with self.lock:
            for nick, q in self.buf.items():
                if not self.ready.get(nick):
                    if self.size[nick] < SAMPLES * 3:      # 60 ms de folga antes de tocar (contra engasgos)
                        continue
                    self.ready[nick] = True
                pos = 0
                while pos < n and q:
                    part = q[0][:n - pos]
                    out[pos:pos + len(part)] += part
                    pos += len(part)
                    if len(part) == len(q[0]):
                        q.popleft()
                    else:
                        q[0] = q[0][len(part):]
                self.size[nick] -= pos
                if pos < n:
                    self.ready[nick] = False               # esvaziou: junta folga de novo
        return np.clip(out, -32768, 32767).astype(np.int16).tobytes()


class MicTrack(MediaStreamTrack):
    kind = "audio"

    def __init__(self):
        super().__init__()
        self.q: asyncio.Queue = asyncio.Queue(maxsize=12)
        self.pts = 0

    def push(self, pcm: bytes):
        if self.q.full():
            self.q.get_nowait()
        self.q.put_nowait(pcm)

    async def recv(self):
        if self.readyState != "live":
            raise MediaStreamError
        try:
            pcm = await asyncio.wait_for(self.q.get(), 1.0)
        except asyncio.TimeoutError:                       # sem microfone: silencio esparso mantem a call viva
            pcm = bytes(SAMPLES * 2)
        f = av.AudioFrame(format="s16", layout="mono", samples=len(pcm) // 2)
        f.planes[0].update(pcm)
        f.sample_rate, f.pts, f.time_base = RATE, self.pts, AUDIO_TB
        self.pts += f.samples
        return f


# ================================================================ tela
def monitors() -> list[dict]:
    """Monitores disponiveis: [{index, w, h}]. Levanta RuntimeError com o motivo quando nao da para capturar."""
    import os
    if sys.platform.startswith("linux") and os.environ.get("XDG_SESSION_TYPE") == "wayland":
        raise RuntimeError("o Wayland nao deixa capturar a tela: saia da sessao e entre com 'no Xorg' (na "
                           "engrenagem da tela de login)")
    import mss
    try:
        with mss.MSS() as s:
            return [{"index": i, "w": m["width"], "h": m["height"]} for i, m in enumerate(s.monitors) if i > 0]
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"nao consegui capturar a tela: {e}") from None


def _cursor_pos() -> tuple[int, int] | None:
    if sys.platform != "win32":
        return None
    import ctypes

    class P(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
    p = P()
    return (p.x, p.y) if ctypes.windll.user32.GetCursorPos(ctypes.byref(p)) else None


def _draw_cursor(img, x: int, y: int, s: int):
    """Seta simples (branca com borda escura): o mss nao captura o ponteiro no Windows."""
    h, w = img.shape[:2]
    for row in range(16 * s):
        r = row // s
        for a, b, color in ((0, r + 2, 20), (1, r, 255)) if r < 14 else ():
            x0, x1, yy = x + a * s, x + min(b, 10) * s, y + row
            if 0 <= yy < h and x1 > 0 and x0 < w and x1 > x0:
                img[yy, max(0, x0):min(w, x1), :3] = color


def fit(w: int, h: int, mw: int, mh: int) -> tuple[int, int]:
    k = min(1.0, mw / w, mh / h)
    return max(2, int(w * k) // 2 * 2), max(2, int(h * k) // 2 * 2)     # VP8 exige lados pares


class ScreenGrabber:
    """Captura a tela numa thread e entrega quadros prontos (yuv420p, no tamanho final)."""

    def __init__(self, monitor: int, preset: str, on_frame, on_error):
        self.monitor, self.on_frame, self.on_error = monitor, on_frame, on_error
        _l, self.mw, self.mh, self.fps = PRESETS[preset]
        self.stop_flag = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="holo-screen")

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_flag.set()

    def _run(self):
        try:
            import mss
            with mss.MSS() as s:
                mon = s.monitors[self.monitor]
                w, h = fit(mon["width"], mon["height"], self.mw, self.mh)
                due = time.monotonic()
                while not self.stop_flag.is_set():
                    img = np.array(s.grab(mon))                            # BGRA
                    cur = _cursor_pos()
                    if cur:
                        _draw_cursor(img, cur[0] - mon["left"], cur[1] - mon["top"],
                                     max(1, round(mon["height"] / 1080)))
                    f = av.VideoFrame.from_ndarray(np.ascontiguousarray(img), format="bgra")
                    self.on_frame(f.reformat(width=w, height=h, format="yuv420p"))
                    due = max(due + 1 / self.fps, time.monotonic() - 0.5)
                    self.stop_flag.wait(max(0.001, due - time.monotonic()))
        except Exception as e:  # noqa: BLE001
            if not self.stop_flag.is_set():
                self.on_error(str(e))


class ScreenTrack(MediaStreamTrack):
    """Sempre presente na conexao; so produz quadros enquanto a tela esta sendo compartilhada."""
    kind = "video"

    def __init__(self):
        super().__init__()
        self.frame = None
        self.event = asyncio.Event()
        self.t0 = time.monotonic()
        self.last_pts = -1

    def push(self, frame):
        self.frame = frame                                 # so o quadro mais novo interessa
        self.event.set()

    async def recv(self):
        if self.readyState != "live":
            raise MediaStreamError
        await self.event.wait()
        self.event.clear()
        src = self.frame
        # cada conexao tem a propria copia: o codificador mexe no pts
        f = av.VideoFrame.from_ndarray(src.to_ndarray(), format="yuv420p")
        f.pts = max(int((time.monotonic() - self.t0) * 90000), self.last_pts + 1)
        f.time_base, self.last_pts = VIDEO_TB, f.pts
        return f


# ================================================================ conexao com um participante
class Peer:
    def __init__(self, eng: "CallEngine", nick: str, offerer: bool):
        self.eng, self.nick, self.offerer = eng, nick, offerer
        cfg = RTCConfiguration(
            iceServers=[RTCIceServer(urls=s["urls"], username=s.get("username"), credential=s.get("credential"))
                        for s in eng.ice],
            iceTransportPolicy=RTCIceTransportPolicy.RELAY if eng.relay_only else RTCIceTransportPolicy.ALL,
            # MAX_BUNDLE junto com canal de dados nao conecta no aiortc 1.16 (o transporte principal e parado)
            bundlePolicy=RTCBundlePolicy.BALANCED)
        self.pc = RTCPeerConnection(cfg)
        self.mic, self.screen = MicTrack(), ScreenTrack()
        self.dc = None
        self.state = "new"
        self.screen_on = False
        self.muted = False
        self.tasks: list[asyncio.Task] = []
        self.latest = None
        self.pending = False
        self.pc.on("connectionstatechange", self._on_state)
        self.pc.on("track", self._on_track)
        self.pc.on("datachannel", self._on_dc)

    def _codecs(self):
        """So Opus e VP8: menos para negociar e um SDP pequeno."""
        for t in self.pc.getTransceivers():
            caps = RTCRtpSender.getCapabilities(t.kind).codecs
            want = [c for c in caps if c.mimeType.lower() in ("audio/opus", "video/vp8", "video/rtx")]
            if t.kind == "video":
                vp8 = [c for c in want if c.mimeType.lower() == "video/vp8"]
                want = vp8 + [c for c in want if c.mimeType.lower() == "video/rtx"]
            t.setCodecPreferences(want)

    async def offer(self):
        self._on_dc(self.pc.createDataChannel("ctl"))
        self.pc.addTrack(self.mic)
        self.pc.addTransceiver(self.screen, direction="sendrecv")
        self._codecs()
        await self.pc.setLocalDescription(await self.pc.createOffer())
        self._send("offer")

    async def accept(self, sdp: str):
        await self.pc.setRemoteDescription(RTCSessionDescription(sdp, "offer"))
        self.pc.addTrack(self.mic)
        self.pc.addTrack(self.screen)
        for t in self.pc.getTransceivers():
            t.direction = "sendrecv"
        self._codecs()
        await self.pc.setLocalDescription(await self.pc.createAnswer())
        self._send("answer")

    async def answered(self, sdp: str):
        if self.pc.signalingState == "have-local-offer":
            await self.pc.setRemoteDescription(RTCSessionDescription(sdp, "answer"))

    def _send(self, kind: str):
        self.eng.emit({"op": "call_signal", "call": self.eng.call_id, "to": self.nick,
                       "data": {"a": kind, "call": self.eng.call_id, "sdp": self.pc.localDescription.sdp}})

    # ------------------------------------------------------------ eventos
    def _on_state(self):
        st = self.pc.connectionState
        if st != self.state:
            self.state = st
            if self.eng.peers.get(self.nick) is not self:      # ja foi trocado ou removido
                return
            self.eng.emit({"op": "call_peer", "call": self.eng.call_id, "nick": self.nick, "state": st})
            if st in ("failed", "closed"):
                asyncio.ensure_future(self.eng._drop(self.nick, st))

    def _on_dc(self, dc):
        if dc.label != "ctl":
            return
        self.dc = dc
        dc.on("message", self._on_ctl)
        dc.on("open", self.send_ctl)
        if dc.readyState == "open":
            self.send_ctl()

    def send_ctl(self):
        if self.dc and self.dc.readyState == "open":
            self.dc.send(json.dumps({"screen": self.eng.grabber is not None, "mute": self.eng.muted}))

    def _on_ctl(self, raw):
        try:
            m = json.loads(raw)
            on, muted = m.get("screen") is True, m.get("mute") is True
        except (ValueError, AttributeError, TypeError):
            return
        if muted != self.muted:
            self.muted = muted
            self.eng.emit({"op": "call_mute", "call": self.eng.call_id, "nick": self.nick, "on": muted})
        if on != self.screen_on:
            self.screen_on = on
            if not on:
                self.latest = None
            self.eng.emit({"op": "call_screen", "call": self.eng.call_id, "nick": self.nick, "on": on})

    def _on_track(self, track):
        fn = self._play if track.kind == "audio" else self._watch
        self.tasks.append(asyncio.ensure_future(fn(track)))

    async def _play(self, track):
        rs = av.AudioResampler(format="s16", layout="mono", rate=RATE)
        last = 0.0
        try:
            while True:
                for f in rs.resample(await track.recv()):
                    pcm = f.to_ndarray().reshape(-1)
                    self.eng.mixer.add(self.nick, pcm)
                    now = time.monotonic()
                    if now - last > 0.2:
                        last = now
                        self.eng.emit({"op": "call_level", "call": self.eng.call_id, "nick": self.nick,
                                       "level": float(np.abs(pcm).mean()) / 32768})
        except MediaStreamError:
            pass

    async def _watch(self, track):
        try:
            while True:
                f = await track.recv()
                # so converte se a janela esta aberta e ja consumiu o quadro anterior
                if self.screen_on and self.nick in self.eng.watching and not self.pending:
                    self.pending = True
                    self.latest = f.to_ndarray(format="rgb24")
                    self.eng.emit({"op": "call_frame", "call": self.eng.call_id, "nick": self.nick})
        except MediaStreamError:
            pass

    async def close(self):
        for t in self.tasks:
            t.cancel()
        self.mic.stop()
        self.screen.stop()
        self.eng.mixer.remove(self.nick)
        try:
            await asyncio.wait_for(self.pc.close(), 5)
        except Exception:  # noqa: BLE001
            pass


# ================================================================ motor
class CallEngine:
    """Uma call em andamento (direta ou de sala). Roda num loop proprio; os metodos publicos podem ser chamados de
    qualquer thread e os avisos saem por on_event(dict), na thread da call."""

    def __init__(self, call_id: str, on_event, ice: list[dict] | None = None, relay_only: bool = False, audio=None):
        if MISSING:
            raise RuntimeError("as dependencias de call nao estao instaladas: " + MISSING)
        self.call_id, self.on_event = call_id, on_event
        self.ice = [s for s in (ice or []) if isinstance(s, dict) and s.get("urls")]
        self.relay_only = relay_only
        self.audio = audio or SoundDevice()
        self.mixer = Mixer()
        self.peers: dict[str, Peer] = {}
        self.muted = False
        self.grabber: ScreenGrabber | None = None
        self.watching: set[str] = set()
        self.closed = False
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._thread, daemon=True, name="holo-call")

    @property
    def has_turn(self) -> bool:
        for s in self.ice:
            urls = s["urls"] if isinstance(s["urls"], list) else [s["urls"]]
            if any(str(u).startswith(("turn:", "turns:")) for u in urls):
                return True
        return False

    def emit(self, ev: dict):
        if not self.closed:
            self.on_event(ev)

    def start(self):
        self.thread.start()
        self._call(self._open_audio)

    def _thread(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
        for t in asyncio.all_tasks(self.loop):
            t.cancel()
        self.loop.run_until_complete(asyncio.sleep(0.05))
        self.loop.close()

    def _call(self, fn, *a):
        if not self.closed and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(fn, *a)

    def _spawn(self, coro_fn, *a):
        async def guard():
            try:
                await coro_fn(*a)
            except Exception as e:  # noqa: BLE001
                self.emit({"op": "call_error", "call": self.call_id, "msg": f"{type(e).__name__}: {e}"[:160]})
        self._call(lambda: asyncio.ensure_future(guard()))

    def _open_audio(self):
        async def run():                # abrir o dispositivo pode demorar: fora do loop
            warns = await self.loop.run_in_executor(
                None, self.audio.start, lambda pcm: self._call(self._on_mic, pcm), self.mixer.fill)
            for w in warns:
                self.emit({"op": "call_error", "call": self.call_id, "msg": w})
            if self.closed:
                self.audio.stop()
        asyncio.ensure_future(run())

    def _on_mic(self, pcm: bytes):
        data = bytes(len(pcm)) if self.muted else pcm
        for p in self.peers.values():
            p.mic.push(data)

    # ------------------------------------------------------------ participantes
    def connect(self, nick: str):
        """Chama o participante (quem recebe so espera a oferta)."""
        self._spawn(self._connect, nick)

    async def _connect(self, nick: str):
        if nick in self.peers or len(self.peers) >= MAX_PEERS - 1:
            return
        p = self.peers[nick] = Peer(self, nick, True)
        self._watchdog(p)
        await p.offer()

    def signal(self, nick: str, data: dict):
        self._spawn(self._signal, nick, data)

    async def _signal(self, nick: str, data: dict):
        sdp = data.get("sdp")
        if not isinstance(sdp, str) or len(sdp) > 20000:
            return
        if data.get("a") == "offer":
            if nick in self.peers:
                await self._drop(nick, "replaced")        # a outra ponta reconectou
            if len(self.peers) >= MAX_PEERS - 1:
                return
            p = self.peers[nick] = Peer(self, nick, False)
            self._watchdog(p)
            await p.accept(sdp)
        elif data.get("a") == "answer" and nick in self.peers and self.peers[nick].offerer:
            await self.peers[nick].answered(sdp)

    def _watchdog(self, p: Peer):
        async def wait():
            await asyncio.sleep(CONNECT_TIMEOUT)
            if self.peers.get(p.nick) is p and p.state != "connected":
                await self._drop(p.nick, "timeout")
        asyncio.ensure_future(wait())

    def remove(self, nick: str, why: str = "left"):
        self._spawn(self._drop, nick, why)

    async def _drop(self, nick: str, why: str):
        p = self.peers.pop(nick, None)
        if not p:
            return
        self.watching.discard(nick)
        if why != "replaced":
            self.emit({"op": "call_gone", "call": self.call_id, "nick": nick, "why": why})
        await p.close()

    # ------------------------------------------------------------ controles
    def _ctl_all(self):
        for p in self.peers.values():
            p.send_ctl()

    def set_mute(self, on: bool):
        self.muted = on
        self._call(self._ctl_all)

    def start_screen(self, monitor: int, preset: str = "equilibrado", grabber=None):
        self.stop_screen()
        g = (grabber or ScreenGrabber)(monitor, preset, lambda f: self._call(self._on_frame, f), self._screen_error)
        self.grabber = g
        g.start()
        self._call(self._ctl_all)

    def _on_frame(self, f):
        if self.grabber:
            for p in self.peers.values():
                p.screen.push(f)

    def _screen_error(self, msg: str):
        self.stop_screen()
        self.emit({"op": "call_screen_stopped", "call": self.call_id, "msg": msg})

    def stop_screen(self):
        g, self.grabber = self.grabber, None
        if g:
            g.stop()
            self._call(self._ctl_all)

    def watch(self, nick: str, on: bool):
        (self.watching.add if on else self.watching.discard)(nick)
        p = self.peers.get(nick)
        if p:
            p.pending = False

    def take_frame(self, nick: str):
        """Quadro mais novo da tela de alguem (RGB), ou None. Libera a conversao do proximo."""
        p = self.peers.get(nick)
        if not p:
            return None
        img, p.latest, p.pending = p.latest, None, False
        return img

    def stop(self):
        """Encerra a call: fecha microfone, tela e todas as conexoes."""
        if self.closed:
            return
        self.stop_screen()
        self.closed = True
        self.audio.stop()

        async def bye():
            await asyncio.gather(*(p.close() for p in self.peers.values()), return_exceptions=True)
            self.peers.clear()
            self.loop.stop()
        if self.thread.is_alive():
            self.loop.call_soon_threadsafe(lambda: asyncio.ensure_future(bye()))
            self.thread.join(timeout=3)
