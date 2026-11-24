"""
Teste das calls: participantes reais (WebRTC nesta maquina) com microfone, alto-falante e tela falsos.

    python tests/test_calls.py
"""
from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import av                                   # noqa: E402
import numpy as np                          # noqa: E402

from arasaka_holo import calls              # noqa: E402


class FakeAudio:
    """Microfone que emite um tom e alto-falante que mede o volume recebido."""

    def __init__(self, hz: int):
        self.hz, self.peak, self.stop_flag = hz, 0, threading.Event()
        self.heard = np.zeros(0, dtype=np.int16)

    def start(self, on_mic, fill):
        def run():
            n, due = 0, time.monotonic()
            while not self.stop_flag.is_set():
                t = np.arange(n, n + calls.SAMPLES) / calls.RATE
                n += calls.SAMPLES
                on_mic((np.sin(2 * np.pi * self.hz * t) * 8000).astype(np.int16).tobytes())
                got = np.frombuffer(fill(calls.SAMPLES), dtype=np.int16)
                self.peak = int(np.abs(got).max())
                self.heard = np.concatenate([self.heard, got])[-calls.RATE:]
                due += 0.02
                time.sleep(max(0, due - time.monotonic()))
        threading.Thread(target=run, daemon=True).start()
        return []

    def tone(self) -> int:
        """Frequencia dominante no ultimo segundo ouvido."""
        spec = np.abs(np.fft.rfft(self.heard))
        return int(np.argmax(spec) * calls.RATE / len(self.heard))

    def stop(self):
        self.stop_flag.set()


class FakeScreen:
    """Tela falsa: metade esquerda vermelha, metade direita azul."""

    def __init__(self, _monitor, _preset, on_frame, _on_error):
        self.on_frame, self.stop_flag = on_frame, threading.Event()

    def start(self):
        img = np.zeros((360, 640, 3), dtype=np.uint8)
        img[:, :320, 0] = 220
        img[:, 320:, 2] = 220

        def run():
            while not self.stop_flag.is_set():
                self.on_frame(av.VideoFrame.from_ndarray(img, format="rgb24").reformat(format="yuv420p"))
                time.sleep(1 / 15)
        threading.Thread(target=run, daemon=True).start()

    def stop(self):
        self.stop_flag.set()


NET = None


class Net:
    """Entrega a sinalizacao entre os motores (no app isso e uma mensagem direta cifrada)."""

    def __init__(self):
        self.eng: dict[str, calls.CallEngine] = {}
        self.ev: dict[str, list] = {}

    def add(self, nick: str, hz: int) -> calls.CallEngine:
        self.ev[nick] = []

        def on_event(e):
            self.ev[nick].append(e)
            if e["op"] == "call_signal" and e["to"] in self.eng:
                assert len(e["data"]["sdp"]) < 12000, "SDP grande demais para uma mensagem"
                self.eng[e["to"]].signal(nick, e["data"])
        e = self.eng[nick] = calls.CallEngine("teste", on_event, ice=[], audio=FakeAudio(hz))
        e.start()
        return e


def until(cond, what: str, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.05)
    raise AssertionError("nao aconteceu: " + what + " " + str([e for e in NET.ev.items()])[:1500] if NET else what)


def main():
    global NET
    net = NET = Net()
    a, b = net.add("A", 440), net.add("B", 880)
    t0 = time.time()
    a.connect("B")
    until(lambda: a.peers and b.peers and a.peers["B"].state == b.peers["A"].state == "connected", "conectar")
    print(f"  conectou em {time.time() - t0:.1f} s")
    until(lambda: a.audio.peak > 3000 and b.audio.peak > 3000, "audio nos dois sentidos")
    time.sleep(1.5)
    assert abs(a.audio.tone() - 880) < 8 and abs(b.audio.tone() - 440) < 8, (a.audio.tone(), b.audio.tone())
    print("  audio nos dois sentidos, sem distorcer o tom")

    a.set_mute(True)
    until(lambda: any(e["op"] == "call_mute" and e["on"] for e in net.ev["B"]), "aviso de mudo")
    until(lambda: b.audio.peak < 100, "mudo silencia")
    a.set_mute(False)
    until(lambda: b.audio.peak > 3000, "voltou do mudo")
    print("  mudo")

    b.start_screen(1, "equilibrado", FakeScreen)
    until(lambda: any(e["op"] == "call_screen" and e["on"] for e in net.ev["A"]), "aviso de tela")
    time.sleep(0.5)
    assert a.take_frame("B") is None, "sem assistir, nao converte quadros"
    a.watch("B", True)
    got = []
    until(lambda: (f := a.take_frame("B")) is not None and (got.append(f) or True), "quadro da tela")
    img = got[0]
    assert img.shape == (360, 640, 3), img.shape
    left, right = img[180, 100].astype(int), img[180, 540].astype(int)
    assert left[0] > 150 and left[2] < 80 and right[2] > 150 and right[0] < 80, (left, right)
    print("  tela chegou com a imagem certa")

    c = net.add("C", 1320)                  # terceiro entra com a tela ja aberta (sala)
    a.connect("C")
    b.connect("C")
    until(lambda: len(c.peers) == 2 and all(p.state == "connected" for p in c.peers.values()), "terceiro conectar")
    until(lambda: any(e["op"] == "call_screen" and e["nick"] == "B" and e["on"] for e in net.ev["C"]), "tela p/ C")
    c.watch("B", True)
    until(lambda: c.take_frame("B") is not None, "quadro para quem entrou depois")
    print("  terceiro participante entrou e ve a tela")

    b.stop_screen()
    until(lambda: any(e["op"] == "call_screen" and not e["on"] for e in net.ev["A"]), "fim da tela")
    b.start_screen(1, "texto", FakeScreen)
    a.watch("B", True)
    until(lambda: a.peers["B"].screen_on and a.take_frame("B") is not None, "segunda transmissao")
    print("  parou e compartilhou de novo")

    c.stop()
    a.remove("C")
    b.remove("C")
    until(lambda: "C" not in a.peers and "C" not in b.peers, "terceiro saiu")
    b.stop()
    until(lambda: any(e["op"] == "call_gone" and e["nick"] == "B" for e in net.ev["A"]), "queda detectada", 60)
    a.stop()
    assert not a.thread.is_alive() and not b.thread.is_alive()

    # 'esconder meu IP' sem TURN: nenhum endereco sai na oferta
    ev = []
    r = calls.CallEngine("privado", ev.append, ice=[], relay_only=True, audio=FakeAudio(440))
    r.start()
    r.connect("X")
    until(lambda: any(e["op"] == "call_signal" for e in ev), "oferta")
    sdp = next(e for e in ev if e["op"] == "call_signal")["data"]["sdp"]
    assert "a=candidate" not in sdp, sdp
    r.stop()
    print("OK: call (audio, mudo, tela, sala com 3, saida, IP escondido)")


if __name__ == "__main__":
    main()
