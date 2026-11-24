"""
Teste da interface: janelas de verdade (sem tela) num servidor local, com conversa, call direta, call de sala e tela.

    QT_QPA_PLATFORM=offscreen python tests/test_gui.py [pasta-dos-prints]
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["ARASAKA_FX"] = "0"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
TMP = Path(tempfile.mkdtemp())
os.environ["ARASAKA_HOLO_HOME"] = str(TMP)

from nacl.signing import SigningKey                                 # noqa: E402
from PySide6.QtWidgets import QApplication, QLabel, QMessageBox     # noqa: E402

from arasaka_holo import app as holo                                # noqa: E402
from arasaka_holo import crypto, server                             # noqa: E402
from arasaka_holo.identity import Identity                          # noqa: E402
from test_calls import FakeAudio, FakeScreen                        # noqa: E402

PORT = 17078
SHOTS = Path(sys.argv[1]) if len(sys.argv) > 1 else None
APP = QApplication([])
holo.load_fonts()
APP.setStyleSheet(holo.stylesheet() + holo.EXTRA_QSS)
BOXES: list[str] = []
ANSWER = [QMessageBox.Yes]
for _n in ("question", "warning", "critical", "information"):        # nenhum dialogo trava o teste
    setattr(QMessageBox, _n, staticmethod(lambda *a, **k: (BOXES.append(str(a[2])), ANSWER[0])[1]))


def until(cond, what: str, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return
        time.sleep(0.01)
    raise AssertionError("nao aconteceu: " + what)


def pause(s: float):
    end = time.time() + s
    until(lambda: time.time() > end, "pausa", s + 5)


def window(nick: str, hz: int) -> holo.MainWindow:
    os.environ["ARASAKA_HOLO_HOME"] = str(TMP / nick)
    st = holo.Store()
    st.data["server"] = os.environ.get("HOLO_TEST_URL") or f"ws://127.0.0.1:{PORT}"
    w = holo.MainWindow(Identity(nick, SigningKey.generate(), "teste"), st)
    w.calls.audio_factory = lambda: FakeAudio(hz)
    w.show()
    return w


def texts(ch) -> str:
    return "\n".join(x.text() for x in ch.view.findChildren(QLabel))


def shot(w, name: str):
    if SHOTS:
        SHOTS.mkdir(parents=True, exist_ok=True)
        APP.processEvents()
        w.grab().save(str(SHOTS / (name + ".png")))


def main():
    ready = threading.Event()

    def run():
        asyncio.run(server.serve("127.0.0.1", PORT, TMP / "srv", quiet=True, ready=ready.set, ice=lambda: []))
    threading.Thread(target=run, daemon=True).start()
    assert ready.wait(10)
    a, b, c = window("AkaiShogun-01BC", 440), window("KuroiRonin-7F3A", 880), window("VoidRaven-0C0C", 1320)
    for w in (a, b, c):
        until(lambda: w.client.connected, "conectar")

    # ---------------------------------------------------------------- conversa
    for w in (a, b, c):
        w.join_room("torre", "senha-bem-grande")
        until(lambda: w.current is not None, "entrar na sala")
    ra, rb, rc = a.current, b.current, c.current
    until(lambda: len(ra.members) == len(rb.members) == len(rc.members) == 3, "todos na sala")
    a.input.setPlainText("ola <b>sala</b>")
    a.send()
    until(lambda: "ola &lt;b&gt;sala" in texts(rb) and "verificado" in texts(rb), "mensagem verificada")
    c.input.setPlainText("oi")
    c.send()
    until(lambda: c.ident.nick in a.store.data["pins"], "c conhecido")
    print("  sala: ok")

    # repeticao pelo servidor e formato antigo
    blob = crypto.seal_room(ra.key, a.ident.sk, a.ident.nick, "unica")
    for _ in range(3):
        b.on_event({"op": "msg", "room": rb.rid, "blob": blob})
    until(lambda: texts(rb).count("unica") == 1, "mensagem")
    assert texts(rb).count("unica") == 1
    # mensagem assinada por outra chave com o nick de alguem
    b.on_event({"op": "msg", "room": rb.rid, "blob": crypto.seal_room(ra.key, SigningKey.generate(), a.ident.nick, "falso")})
    until(lambda: "NAO CONFERE" in texts(rb), "assinatura falsa marcada")
    for junk in ({"op": "dm"}, {"op": "dm", "from": "x", "from_pk": 1, "blob": 2}, {"op": "whois", "nick": None},
                 {"op": "msg", "room": rb.rid}, {"op": "call_frame", "call": ""}, {"op": 5}, {}):
        b.on_event(junk)
    print("  repeticao, assinatura falsa e lixo: ok")

    # ---------------------------------------------------------------- call direta
    a.open_dm(b.ident.nick)
    until(lambda: a.current.peer_pk, "chave do contato")
    a.calls.call()
    until(lambda: b.calls.phase == "in", "tocar")
    shot(b, "call-recebida")
    b.calls.answer()
    until(lambda: a.calls.states.get(b.ident.nick) == b.calls.states.get(a.ident.nick) == "connected", "call conectada")
    until(lambda: a.calls.engine.audio.peak > 3000 and b.calls.engine.audio.peak > 3000, "audio")
    b.calls.toggle_mute()
    until(lambda: b.ident.nick in a.calls.muted, "mudo aparece")
    b.calls.engine.start_screen(1, "equilibrado", FakeScreen)
    until(lambda: b.ident.nick in a.calls.screens, "aviso de tela")
    a.calls.view(b.ident.nick)
    until(lambda: a.calls.windows[b.ident.nick].img is not None, "quadro na janela")
    img = a.calls.windows[b.ident.nick].img
    assert img.pixelColor(100, 180).red() > 150 and img.pixelColor(540, 180).blue() > 150
    pause(0.5)
    shot(a, "call-direta")
    shot(a.calls.windows[b.ident.nick], "tela-recebida")
    c.open_dm(a.ident.nick)
    until(lambda: c.current.peer_pk, "chave")
    c.calls.call()
    until(lambda: c.calls.phase == "idle" and "outra call" in texts(c.current), "ocupado")
    b.calls.engine.stop_screen()
    until(lambda: not a.calls.windows, "janela fecha sozinha")
    a.calls.hangup()
    until(lambda: b.calls.phase == "idle" and a.calls.phase == "idle", "desligar")
    fim = texts(b.channels["dm:" + a.ident.nick])
    assert "desligou" in fim or "saiu da call" in fim     # o aviso direto pode chegar antes do relay
    print("  call direta (tocar, atender, audio, mudo, tela, ocupado, desligar): ok")

    a.calls.call()
    until(lambda: b.calls.phase == "in", "tocar 2")
    b.calls.decline()
    until(lambda: a.calls.phase == "idle", "recusar")
    a.calls.call()
    until(lambda: b.calls.phase == "in", "tocar 3")
    a.calls.hangup()
    until(lambda: b.calls.phase == "idle", "cancelar")
    b.open_dm(a.ident.nick)                     # os dois ligam ao mesmo tempo
    until(lambda: b.current.peer_pk, "chave")
    a.calls.call()
    b.calls.call()
    until(lambda: a.calls.states.get(b.ident.nick) == b.calls.states.get(a.ident.nick) == "connected", "ligacoes cruzadas")
    b.calls.hangup()
    until(lambda: a.calls.phase == "idle", "fim")
    b.store.data["accept_calls"] = "none"
    a.calls.call()
    pause(1)
    assert b.calls.phase == "idle" and "bloqueada" in texts(b.channels["dm:" + a.ident.nick])
    a.calls.hangup()
    b.store.data["accept_calls"] = "known"
    a.store.data["hide_ip"] = True
    a.calls.call()
    assert a.calls.phase == "idle" and "TURN" in BOXES[-1], "sem TURN nao expoe o IP"
    a.store.data["hide_ip"] = False
    print("  recusar, cancelar, ligacoes cruzadas, bloqueio, esconder IP: ok")

    # ---------------------------------------------------------------- call de sala
    for w, r in ((a, ra), (b, rb), (c, rc)):
        w.select_channel(r)
        w.calls.call()
    until(lambda: all(sorted(w.calls.states.values()) == ["connected"] * 2 for w in (a, b, c)), "sala com 3")
    pause(0.6)
    shot(c, "call-sala")
    b.calls.hangup()
    until(lambda: b.ident.nick not in a.calls.states and b.ident.nick not in c.calls.states, "b saiu")
    b.select_channel(rb)
    b.calls.call()
    until(lambda: all(sorted(w.calls.states.values()) == ["connected"] * 2 for w in (a, b, c)), "b voltou")
    c.close()                                   # fechou o app no meio da call
    until(lambda: c.ident.nick not in a.calls.states and c.ident.nick not in b.calls.states, "c fechou o app")
    until(lambda: a.calls.states.get(b.ident.nick) == "connected", "a e b seguem")
    print("  call de sala (3 pessoas, sair, voltar, fechar o app): ok")

    # ---------------------------------------------------------------- panico e chave trocada
    b.store.data.update(remember_rooms=True, rooms=[{"name": "torre", "pw": "x"}])
    b.panic()
    assert not b.channels and b.calls.phase == "idle" and not b.store.data["rooms"]
    until(lambda: b.ident.nick not in a.calls.states, "panico sai da call")
    a.calls.hangup()
    pk2 = crypto.b64(bytes(SigningKey.generate().verify_key))
    ch = a.channels["dm:" + b.ident.nick]
    old = ch.peer_pk
    a.pending_dm[b.ident.nick] = ch
    a.on_whois({"nick": b.ident.nick, "pk": pk2, "online": True})
    a.select_channel(ch)
    ANSWER[0] = QMessageBox.No
    a.input.setPlainText("nao pode sair")
    a.send()
    assert ch.peer_pk == old and "nao pode sair" not in texts(ch), "enviou para chave nao confirmada"
    # ---------------------------------------------------------------- erro de conexao visivel
    assert not a.err_bar.isVisible()
    good = a.store.data["server"]
    a.store.data["server"] = "http://127.0.0.1:9/"
    t0 = time.time()
    a.connect_server()
    assert time.time() - t0 < 1, "trocar de servidor travou a janela"
    until(lambda: a.err_bar.isVisible() and "recusada" in a.err_lbl.text(), "motivo na barra")
    pause(2.5)
    assert a.err_bar.isVisible(), "o motivo fica ate conectar"
    shot(a, "erro-conexao")
    dg = holo.DiagDialog(a)
    dg.show()
    until(lambda: dg.copy_btn.isEnabled(), "diagnostico", 40)
    assert "ERRO" in dg.report and "ultimo erro no app" in dg.report and a.ident.nick not in dg.report, dg.report
    dg.copy()
    assert QApplication.clipboard().text() == dg.report
    shot(dg, "diagnostico-erro")
    dg.close()
    a.store.data["server"] = good
    a.connect_server()
    until(lambda: a.client.connected and not a.err_bar.isVisible() and "ONLINE" in a.state_lbl.text(), "barra some", 40)
    pause(4)
    assert "ONLINE" in a.state_lbl.text(), "aviso atrasado da conexao antiga"
    a.on_event({"op": "error", "code": "nick_taken", "msg": "este nick ja pertence a outra chave"})
    assert a.err_bar.isVisible() and "outra chave" in a.err_lbl.text() and "NICK" not in a.state_lbl.toolTip()
    a.show_error("")
    hook = sys.excepthook
    holo.install_error_dialog(a)
    n = len(BOXES)
    for _ in range(3):
        try:
            raise ValueError("segredo-da-conversa")
        except ValueError:
            sys.excepthook(*sys.exc_info())
    pause(0.3)
    sys.excepthook = hook
    assert len(BOXES) == n + 1 and "ValueError" in BOXES[-1], "erro inesperado aparece uma vez"
    log = (a.store.dir / "errors.log").read_text(encoding="utf-8")
    assert "ValueError test_gui.py" in log and "segredo" not in log, log
    print("  erro de conexao, diagnostico e erro inesperado na tela: ok")
    d = holo.SettingsDialog(a)
    d.show()
    shot(d, "config")
    d.close()
    j = holo.JoinDialog(a)
    j.generate()
    assert len(j.pw.text()) == 23
    for w in (a, b):
        w.close()
    print("OK: interface")


if __name__ == "__main__":
    main()
    sys.stdout.flush()
    os._exit(0)
