"""
ARASAKA HOLO // calls na interface: barra da call, janela da tela compartilhada e a sinalizacao.

Direta:  invite -> accept / decline / busy -> offer -> answer ... hangup   (mensagens diretas cifradas)
Sala:    join -> here ... leave  (mensagens da sala) e offer / answer entre cada par (mensagens diretas)

O microfone so abre depois que a pessoa atende ou entra na call; o IP so vai para quem ja esta nela.
"""
from __future__ import annotations

import os
import re
import threading
import time

from PySide6.QtCore import QObject, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QImage, QPainter
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QLabel,
                               QMessageBox, QPushButton, QSlider, QVBoxLayout, QWidget)

from . import calls
from .kit import BaseDialog, button, label

RING_TIMEOUT = 45
ICE_RE = re.compile(r"(stun|turn|turns):[A-Za-z0-9.\-\[\]:]+(\?transport=(udp|tcp))?")


def clean_ice(servers) -> list[dict]:
    """So aceita do servidor enderecos STUN/TURN bem formados."""
    out = []
    for s in servers if isinstance(servers, list) else []:
        if not isinstance(s, dict):
            continue
        urls = s.get("urls")
        urls = [u for u in (urls if isinstance(urls, list) else [urls]) if isinstance(u, str) and ICE_RE.fullmatch(u)]
        if urls:
            d = {"urls": urls[:4]}
            if isinstance(s.get("username"), str) and isinstance(s.get("credential"), str):
                d.update(username=s["username"], credential=s["credential"])
            out.append(d)
    return out[:8]


class ScreenWindow(QWidget):
    closed = Signal(str)

    def __init__(self, nick: str):
        super().__init__()
        self.nick = nick
        self.img: QImage | None = None
        self.setWindowTitle(f"TELA DE {nick}  //  duplo clique: tela cheia")
        self.resize(1060, 620)
        self.setMinimumSize(320, 180)

    def set_frame(self, arr):
        h, w = arr.shape[:2]
        self.img = QImage(arr.tobytes(), w, h, 3 * w, QImage.Format_RGB888).copy()
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(0, 0, 0))
        if not self.img:
            p.setPen(QColor(140, 140, 150))
            p.drawText(self.rect(), Qt.AlignCenter, "recebendo a tela...")
            return
        p.setRenderHint(QPainter.SmoothPixmapTransform)
        s = self.img.size().scaled(self.size(), Qt.KeepAspectRatio)
        p.drawImage(QRectF((self.width() - s.width()) / 2, (self.height() - s.height()) / 2, s.width(), s.height()),
                    self.img)

    def mouseDoubleClickEvent(self, _e):
        self.showNormal() if self.isFullScreen() else self.showFullScreen()

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Escape and self.isFullScreen():
            self.showNormal()

    def closeEvent(self, e):
        self.closed.emit(self.nick)
        e.accept()


class ShareDialog(BaseDialog):
    def __init__(self, parent, mons: list[dict]):
        super().__init__(parent, "COMPARTILHAR TELA", "Todos da call vao poder ver o monitor escolhido")
        f = QFormLayout()
        self.mon = QComboBox()
        for m in mons:
            self.mon.addItem(f"Monitor {m['index']}  ({m['w']} x {m['h']})", m["index"])
        f.addRow(label("MONITOR", "muted", 2, bold=True), self.mon)
        self.preset = QComboBox()
        for k, (t, *_x) in calls.PRESETS.items():
            self.preset.addItem(t, k)
        self.preset.setCurrentIndex(list(calls.PRESETS).index("equilibrado"))
        f.addRow(label("QUALIDADE", "muted", 2, bold=True), self.preset)
        self.lay.addLayout(f)
        self.lay.addWidget(label("Tudo o que aparecer nesse monitor sera visto: notificacoes, outras conversas e "
                                 "senhas. Feche o que for particular antes.", "muted", 0.3, wrap=True))
        self.add_buttons("COMPARTILHAR")


def percent(v, default=100) -> int:
    """Volume salvo em disco: aceita so numeros, de 0 a 200."""
    return max(0, min(200, v)) if type(v) is int else default


class VolumeRow:
    """Uma linha do painel SOM: nome, controle de 0 a 200%, valor e silenciar."""

    def __init__(self, grid: QGridLayout, row: int, name: str, on_change, mute: bool = True):
        self.name = label(name, None, 0.5, 13, True)
        self.slider = QSlider(Qt.Horizontal)
        self.slider.setRange(0, 200)
        self.slider.setPageStep(10)
        self.value = QPushButton("100%")
        self.value.setProperty("kind", "ghost")
        self.value.setFixedWidth(72)
        self.value.setToolTip("Voltar para 100%")
        self.mute = button("SILENCIAR", None, self._toggle) if mute else None
        self.on_change = on_change
        self.silent = False
        self.value.clicked.connect(lambda _c=False: self.slider.setValue(100))
        self.slider.valueChanged.connect(lambda _v: self._changed())
        for col, w in enumerate((self.name, self.slider, self.value, self.mute)):
            if w:
                grid.addWidget(w, row, col)

    def set(self, v: int, silent: bool = False):
        self.slider.blockSignals(True)
        self.slider.setValue(v)
        self.slider.blockSignals(False)
        self.silent = silent
        self._paint()

    def _toggle(self):
        self.silent = not self.silent
        self._paint()
        self.on_change(self.slider.value(), self.silent)

    def _changed(self):
        self.silent = False                      # mexeu no volume: quer ouvir
        self._paint()
        self.on_change(self.slider.value(), self.silent)

    def _paint(self):
        self.value.setText(f"{self.slider.value()}%")
        if self.mute:
            self.mute.setText("OUVIR" if self.silent else "SILENCIAR")
        self.name.setStyleSheet("color: #55555e;" if self.silent else "color: #ececf0;")

    def remove(self, grid: QGridLayout):
        for w in (self.name, self.slider, self.value, self.mute):
            if w:
                grid.removeWidget(w)
                w.deleteLater()


class SoundPanel(QFrame):
    """Volumes da call. Valem so neste PC (menos o do microfone, que muda o que os outros ouvem)."""

    def __init__(self, mgr: "CallManager"):
        super().__init__()
        self.mgr = mgr
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 6, 0, 4)
        self.grid.setHorizontalSpacing(14)
        self.grid.setVerticalSpacing(6)
        self.grid.setColumnStretch(1, 1)
        self.rows: dict[str, VolumeRow] = {}
        self.next = 2
        self.master = VolumeRow(self.grid, 0, "VOLUME GERAL", lambda v, _s: mgr.set_level("vol_master", v), mute=False)
        self.mic = VolumeRow(self.grid, 1, "SEU MICROFONE", lambda v, _s: mgr.set_level("vol_mic", v), mute=False)
        self.hide()

    def sync(self, nicks: list[str]):
        for n in [n for n in self.rows if n not in nicks]:
            self.rows.pop(n).remove(self.grid)
        for n in nicks:
            if n not in self.rows:
                r = self.rows[n] = VolumeRow(self.grid, self.next, n, lambda v, s, n=n: self.mgr.set_volume(n, v, s))
                self.next += 1
                r.set(*self.mgr.volume(n))

    def load(self):
        d = self.mgr.win.store.data
        self.master.set(percent(d.get("vol_master")))
        self.mic.set(percent(d.get("vol_mic")))


class CallBar(QFrame):
    def __init__(self, mgr: "CallManager"):
        super().__init__()
        self.setObjectName("callbar")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 8, 22, 8)
        row = QHBoxLayout()
        self.status = label("", "red", 2, 12, True)
        row.addWidget(self.status)
        row.addSpacing(12)
        self.people = QLabel("")
        self.people.setTextFormat(Qt.RichText)
        self.people.setWordWrap(True)
        self.people.linkActivated.connect(lambda _n: mgr.toggle_sound(True))
        self.people.setToolTip("Clique num nick para ajustar o volume")
        row.addWidget(self.people, 1)
        self.answer = button("ATENDER", "primary", mgr.answer)
        self.decline = button("RECUSAR", "danger", mgr.decline)
        self.mute = button("MUDO", None, mgr.toggle_mute, "Liga e desliga o microfone (Ctrl+M)")
        self.share = button("TELA", None, mgr.toggle_share, "Compartilha a sua tela")
        self.sound = button("SOM", None, mgr.toggle_sound, "Volume de cada pessoa, geral e do seu microfone")
        self.hang = button("SAIR", "danger", mgr.hangup, "Sai da call")
        for b in (self.answer, self.decline, self.mute, self.sound, self.share, self.hang):
            row.addWidget(b)
        lay.addLayout(row)
        self.views = QHBoxLayout()
        self.views.addStretch()
        lay.addLayout(self.views)
        self.view_btns: dict[str, object] = {}
        self.panel = SoundPanel(mgr)
        lay.addWidget(self.panel)
        self.hide()

    def set_views(self, nicks: list[str], slot):
        for n in [n for n in self.view_btns if n not in nicks]:
            b = self.view_btns.pop(n)
            self.views.removeWidget(b)
            b.deleteLater()
        for n in nicks:
            if n not in self.view_btns:
                b = self.view_btns[n] = button(f"VER TELA DE {n}", "primary", lambda n=n: slot(n))
                self.views.insertWidget(self.views.count() - 1, b)


class CallManager(QObject):
    """Estado da call desta janela. Fases: idle, out (chamando), in (tocando), on (na call)."""
    stopped = Signal()

    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.phase = "idle"
        self.kind = ""                       # dm | room
        self.call_id = ""
        self.cid = ""                        # canal da call
        self.peer = ""                       # quem esta do outro lado (direta)
        self.peer_pk = ""
        self.trusted: dict[str, str] = {}    # nick -> chave verificada de quem esta na call
        self.held: dict[str, list[dict]] = {}   # ofertas que chegaram antes do 'here' ser verificado
        self.engine = None
        self.states: dict[str, str] = {}
        self.muted: set[str] = set()
        self.levels: dict[str, float] = {}
        self.screens: set[str] = set()
        self.windows: dict[str, ScreenWindow] = {}
        self.since = 0.0
        self.deadline = 0.0
        self.rooms: dict[str, set[str]] = {}    # cid -> quem esta na call da sala (para o botao)
        self.audio_factory = None            # testes
        self.bar = CallBar(self)
        self.save_timer = QTimer(self)       # arrastar o volume nao grava o disco a cada passo
        self.save_timer.setSingleShot(True)
        self.save_timer.timeout.connect(self.win.store.save)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.ice_timer = QTimer(self)        # a credencial TURN expira: renova de hora em hora
        self.ice_timer.timeout.connect(lambda: self.win.client and self.win.client.send({"op": "ice"}))
        self.ice_timer.start(3600_000)

    # ------------------------------------------------------------ util
    def _ch(self, cid: str | None = None):
        return self.win.channels.get(cid or self.cid)

    def say(self, text: str, color="#8c8c96", cid: str | None = None):
        ch = self._ch(cid)
        if ch:
            ch.view.add_system(text, color)
        else:
            self.win.toast(text, color)

    def send_dm(self, nick: str, pk: str, data: dict):
        self.win.send_data(nick, pk, data)

    def busy(self) -> bool:
        return self.phase != "idle"

    def ready(self) -> bool:
        """Confere tudo antes de entrar numa call (dependencias, conexao, aviso de IP)."""
        w = self.win
        if not calls.available():
            QMessageBox.warning(w, "Call indisponivel", "Faltam as dependencias de call. Rode o instalador de novo.\n\n"
                                + calls.MISSING)
            return False
        if not w.client or not w.client.connected:
            w.toast("sem conexao com o servidor")
            return False
        turn = any(u.startswith("turn") for s in w.ice for u in s["urls"])
        if w.store.data.get("hide_ip"):
            if not turn:
                QMessageBox.warning(w, "Sem TURN", "'Esconder meu IP' esta ligado, mas este servidor nao tem TURN para "
                                    "repassar a call.\n\nConfigure o TURN no servidor ou desligue a opcao em CONFIG.")
                return False
        elif not w.store.data.get("call_ip_ok"):
            r = QMessageBox.question(
                w, "Call direta entre os PCs",
                "A call e cifrada de ponta a ponta e vai direto de um PC para o outro. Por isso, quem estiver na call "
                "consegue ver o seu IP" + (", e o servidor STUN tambem" if w.ice else "") + ".\n\n"
                "Para nao mostrar, ligue 'Esconder meu IP' em CONFIG (precisa de TURN no servidor) ou use VPN.\n\n"
                "Continuar?")
            if r != QMessageBox.Yes:
                return False
            w.store.data["call_ip_ok"] = True
            w.store.save()
        return True

    def _engine(self):
        d = self.win.store.data
        audio = self.audio_factory() if self.audio_factory else calls.SoundDevice(d.get("mic", ""),
                                                                                  d.get("speaker", ""))
        self.engine = calls.CallEngine(self.call_id, self.win.bridge.event.emit, self.win.ice,
                                       bool(d.get("hide_ip")), audio)
        self.engine.set_levels(percent(d.get("vol_master")) / 100, percent(d.get("vol_mic")) / 100)
        self.engine.start()
        self.bar.panel.load()
        self.phase, self.since = "on", time.time()
        self.timer.start(300)

    # ------------------------------------------------------------ direta
    def call(self):
        """Botao CALL: liga para o contato ou entra na call da sala."""
        ch = self.win.current
        if not ch:
            return
        if self.busy():
            return self.win.toast("voce ja esta em uma call")
        if ch.kind == "dm" and (not ch.peer_pk or ch.changed_pk):
            return self.win.toast("ainda buscando a chave do contato..." if not ch.peer_pk else
                                  "a chave do contato mudou: confirme com a pessoa antes de ligar")
        if not self.ready():
            return
        self.cid, self.kind = ch.cid, ch.kind
        if ch.kind == "dm":
            self.peer, self.peer_pk = ch.peer, ch.peer_pk
            self.trusted = {ch.peer: ch.peer_pk}
            self.call_id = "dm:" + os.urandom(12).hex()
            self.phase, self.deadline = "out", time.time() + RING_TIMEOUT
            self.send_dm(self.peer, self.peer_pk, {"a": "invite", "call": self.call_id})
            self.say(f"chamando {self.peer}...")
            self.timer.start(300)
        else:
            self.call_id = "room:" + ch.rid
            self._engine()
            self.win.send_room_data(ch, {"a": "join"})
            self.say("voce entrou na call da sala")
        self.refresh()

    def answer(self):
        if self.phase != "in" or not self.ready():
            return
        self._engine()
        self.send_dm(self.peer, self.peer_pk, {"a": "accept", "call": self.call_id})
        self.refresh()

    def decline(self):
        if self.phase == "in":
            self.send_dm(self.peer, self.peer_pk, {"a": "decline", "call": self.call_id})
            self._reset("call recusada")

    def hangup(self):
        if self.phase == "idle":
            return
        if self.phase == "in":
            return self.decline()
        ch = self._ch()
        if self.kind == "dm":
            self.send_dm(self.peer, self.peer_pk, {"a": "hangup", "call": self.call_id})
        elif ch:
            self.win.send_room_data(ch, {"a": "leave"})
        self._reset("call encerrada")

    def on_dm(self, nick: str, pk: str, body: dict, known: bool):
        """Sinalizacao que chegou por mensagem direta (ja conferida: assinatura, chave do nick e repeticao)."""
        d, a, cid = body["d"], body["d"].get("a"), body["d"].get("call")
        if not isinstance(cid, str) or len(cid) > 80:
            return
        if a == "invite":
            return self._invited(nick, pk, cid, known)
        if cid != self.call_id or self.phase == "idle":
            return
        if a in ("offer", "answer"):
            if self.phase != "on":
                return
            if self.trusted.get(nick) == pk:
                self.engine.signal(nick, d)
            elif self.kind == "room" and len(self.held) < 8:
                self.held.setdefault(nick, []).append({"pk": pk, "d": d})
            return
        if self.kind != "dm" or nick != self.peer or pk != self.peer_pk:
            return
        if a == "accept" and self.phase == "out":
            self._engine()
            self.engine.connect(nick)
            self.refresh()
        elif a in ("decline", "busy", "hangup") and (self.phase != "on" or a == "hangup"):
            self._reset({"decline": f"{nick} recusou a call", "busy": f"{nick} esta em outra call",
                         "hangup": f"{nick} desligou" if self.phase == "on" else f"{nick} cancelou a call"}[a])

    def _invited(self, nick: str, pk: str, cid: str, known: bool):
        policy = self.win.store.data.get("accept_calls", "known")
        if not cid.startswith("dm:"):
            return
        if policy == "none" or (policy == "known" and not known) or not calls.available():
            self.say(f"call de {nick} bloqueada (CONFIG > CALLS)", "#ffb347", "dm:" + nick)
            return
        if self.busy():
            # os dois ligaram um para o outro ao mesmo tempo: o maior nick atende o menor
            if self.phase == "out" and nick == self.peer and pk == self.peer_pk:
                if self.win.ident.nick > nick:
                    self.call_id = cid
                    self._engine()
                    self.send_dm(nick, pk, {"a": "accept", "call": cid})
                    self.refresh()
                return
            return self.send_dm(nick, pk, {"a": "busy", "call": cid})
        self.kind, self.peer, self.peer_pk, self.call_id, self.cid = "dm", nick, pk, cid, "dm:" + nick
        self.trusted = {nick: pk}
        self.phase, self.deadline = "in", time.time() + RING_TIMEOUT
        self.say(f"{nick} esta ligando", "#ff2e40")
        self.timer.start(300)
        self.refresh()

    # ------------------------------------------------------------ sala
    def on_room(self, ch, body: dict):
        """Sinalizacao da sala (ja conferida: assinatura e chave do nick)."""
        nick, pk, a = body["n"], body["k"], body["d"].get("a")
        if nick == self.win.ident.nick or a not in ("join", "here", "leave"):
            return
        mine = self.phase == "on" and self.kind == "room" and self.cid == ch.cid
        who = self.rooms.setdefault(ch.cid, set())
        if a == "leave":
            who.discard(nick)
            self.left_room(ch, nick)
        else:
            if nick not in who:
                who.add(nick)
                if a == "join":
                    ch.view.add_system(f"{nick} entrou na call da sala", "#8c8c96")
            if mine:
                if a == "join":
                    self.win.send_room_data(ch, {"a": "here"})
                    if nick in self.states:           # entrou de novo (caiu e voltou): conexao nova
                        self.engine.remove(nick, "replaced")
                        self._forget(nick)
                if len(self.trusted) >= calls.MAX_PEERS - 1 and nick not in self.trusted:
                    self.say(f"call cheia (ate {calls.MAX_PEERS}): sem conexao com {nick}", "#ffb347")
                else:
                    self.trusted[nick] = pk
                    for h in self.held.pop(nick, []):
                        if h["pk"] == pk:
                            self.engine.signal(nick, h["d"])
                    if self.win.ident.nick < nick:    # em cada par, o menor nick faz a oferta
                        self.engine.connect(nick)
        self.refresh()

    def left_room(self, ch, nick: str):
        """Saiu da call ou da sala."""
        self.rooms.get(ch.cid, set()).discard(nick)
        if self.phase == "on" and self.cid == ch.cid and nick in self.trusted:
            self.trusted.pop(nick)
            self.engine.remove(nick)
        self.refresh()

    # ------------------------------------------------------------ eventos do motor (thread da interface)
    def on_event(self, ev: dict):
        if ev.get("call") != self.call_id or self.phase != "on":
            return
        op, nick = ev["op"], ev.get("nick", "")
        if op == "call_signal":
            pk = self.trusted.get(ev["to"])
            if pk:
                self.send_dm(ev["to"], pk, ev["data"])
        elif op == "call_peer":
            self.states[nick] = ev["state"]
            if ev["state"] == "connected":
                self.say(f"{nick} na call")
        elif op == "call_gone":
            self._forget(nick)
            if ev["why"] != "left":
                self.trusted.pop(nick, None)
            why = {"timeout": f"nao deu para conectar com {nick}: a rede de um dos dois bloqueia conexao direta (use "
                              "um servidor TURN)", "failed": f"a conexao com {nick} caiu"}.get(ev["why"], f"{nick} saiu da call")
            self.say(why, "#ffb347" if ev["why"] in ("timeout", "failed") else "#8c8c96")
            if self.kind == "dm":
                if ev["why"] != "left":
                    self.send_dm(self.peer, self.peer_pk, {"a": "hangup", "call": self.call_id})
                return self._reset("call encerrada")
        elif op == "call_mute":
            (self.muted.add if ev["on"] else self.muted.discard)(nick)
        elif op == "call_level":
            self.levels[nick] = ev["level"]
            return
        elif op == "call_screen":
            if ev["on"]:
                self.screens.add(nick)
                self.say(f"{nick} esta compartilhando a tela", "#ff2e40")
                QApplication.alert(self.win, 0)
            else:
                self.screens.discard(nick)
                self._close_window(nick)
        elif op == "call_frame":
            win = self.windows.get(nick)
            img = self.engine.take_frame(nick)
            if win and img is not None:
                win.set_frame(img)
            return
        elif op == "call_screen_stopped":
            self.say("o compartilhamento parou: " + ev["msg"], "#ffb347")
        elif op == "call_error":
            self.say("call: " + ev["msg"], "#ffb347")
        self.refresh()

    def _forget(self, nick: str):
        for d in (self.states, self.levels):
            d.pop(nick, None)
        for s in (self.muted, self.screens):
            s.discard(nick)
        self._close_window(nick)

    # ------------------------------------------------------------ som
    def volume(self, nick: str) -> tuple[int, bool]:
        """(0 a 200, silenciado) que voce escolheu para a pessoa."""
        vols = self.win.store.data.get("volumes")
        v = vols.get(nick) if isinstance(vols, dict) else None
        return (percent(v.get("v")), v.get("m") is True) if isinstance(v, dict) else (100, False)

    def set_volume(self, nick: str, v: int, silent: bool):
        d = self.win.store.data
        if not isinstance(d.get("volumes"), dict):
            d["volumes"] = {}
        if v == 100 and not silent:
            d["volumes"].pop(nick, None)
        else:
            d["volumes"][nick] = {"v": v, "m": silent}
        self._apply_volume(nick)
        self.save_timer.start(600)
        self.refresh()

    def _apply_volume(self, nick: str):
        if self.engine:
            v, silent = self.volume(nick)
            self.engine.set_volume(nick, 0.0 if silent else v / 100)

    def set_level(self, key: str, v: int):
        d = self.win.store.data
        d[key] = v
        if self.engine:
            self.engine.set_levels(percent(d.get("vol_master")) / 100, percent(d.get("vol_mic")) / 100)
        self.save_timer.start(600)

    def toggle_sound(self, show: bool | None = None):
        p = self.bar.panel
        p.setVisible(p.isHidden() if show is None else show)
        self.refresh()

    # ------------------------------------------------------------ controles
    def toggle_mute(self):
        if self.engine:
            self.engine.set_mute(not self.engine.muted)
            self.refresh()

    def toggle_share(self):
        if not self.engine:
            return
        if self.engine.grabber:
            self.engine.stop_screen()
            self.say("voce parou de compartilhar a tela")
            return self.refresh()
        try:
            mons = calls.monitors()
        except RuntimeError as e:
            QMessageBox.warning(self.win, "Compartilhar tela", str(e))
            return
        d = ShareDialog(self.win, mons)
        if d.exec() == QDialog.Accepted and self.engine:       # a call pode ter caido com a janela aberta
            self.engine.start_screen(d.mon.currentData(), d.preset.currentData())
            self.say("voce esta compartilhando a tela", "#ff2e40")
        self.refresh()

    def view(self, nick: str):
        if not self.engine or nick not in self.screens:
            return
        w = self.windows.get(nick)
        if not w:
            w = self.windows[nick] = ScreenWindow(nick)
            w.closed.connect(self._window_closed)
            self.engine.watch(nick, True)
        w.show()
        w.raise_()
        w.activateWindow()

    def _window_closed(self, nick: str):
        w = self.windows.pop(nick, None)
        if w:
            w.deleteLater()
            if self.engine:
                self.engine.watch(nick, False)

    def _close_window(self, nick: str):
        w = self.windows.get(nick)
        if w:
            w.close()

    def _reset(self, text: str = ""):
        eng, self.engine = self.engine, None
        if text and self.phase != "idle":
            self.say(text)
        self.phase, self.call_id, self.kind, self.peer, self.peer_pk, self.cid = "idle", "", "", "", "", ""
        self.trusted, self.held = {}, {}
        for n in list(self.windows):
            self._close_window(n)
        self.states.clear()
        self.levels.clear()
        self.muted.clear()
        self.screens.clear()
        self.timer.stop()
        if eng:                                  # fechar as conexoes leva um instante: fora da interface
            threading.Thread(target=eng.stop, daemon=True, name="holo-call-stop").start()
        self.refresh()
        return eng

    def shutdown(self):
        """Fechando o app ou panico: avisa os outros e solta microfone e tela."""
        eng = self.engine
        self.hangup()
        if eng:
            eng.stop()

    def forget_rooms(self):
        self.rooms.clear()

    # ------------------------------------------------------------ interface
    def _tick(self):
        now = time.time()
        if self.phase == "out" and now > self.deadline:
            self.send_dm(self.peer, self.peer_pk, {"a": "hangup", "call": self.call_id})
            return self._reset(f"{self.peer} nao atendeu")
        if self.phase == "in":
            if now > self.deadline:
                return self._reset(f"call perdida de {self.peer}")
            if int(now * 10) % 20 < 3:
                QApplication.beep()
                QApplication.alert(self.win, 0)
        if self.phase == "on" and self.kind == "dm" and not self.states and now - self.since > calls.CONNECT_TIMEOUT + 10:
            return self._reset(f"{self.peer} nao respondeu")
        for n in self.levels:
            self.levels[n] *= 0.6
        self.refresh()

    def refresh(self):
        b = self.bar
        self.win.update_call_button()
        b.setVisible(self.phase != "idle")
        if self.phase == "idle":
            b.panel.hide()
            b.panel.sync([])
            return b.set_views([], self.view)
        on = self.phase == "on"
        b.answer.setVisible(self.phase == "in")
        b.decline.setVisible(self.phase == "in")
        b.mute.setVisible(on)
        b.share.setVisible(on)
        b.sound.setVisible(on)
        if not on:
            b.panel.hide()
        b.hang.setVisible(self.phase != "in")
        ch = self._ch()
        where = ("#" + ch.title) if ch and self.kind == "room" else ""
        if on:
            s = int(time.time() - self.since)
            b.status.setText(f"■ CALL {where}  {s // 60:02d}:{s % 60:02d}")
            b.mute.setText("ATIVAR MIC" if self.engine.muted else "MUDO")
            b.share.setText("PARAR TELA" if self.engine.grabber else "TELA")
        else:
            b.status.setText("■ CHAMANDO" if self.phase == "out" else "■ CALL RECEBIDA")
        names = sorted(set(self.trusted) | set(self.states))
        b.sound.setText("FECHAR SOM" if not b.panel.isHidden() else "SOM")
        if on:
            b.panel.sync(names)
            for n in names:
                self._apply_volume(n)
        parts = []
        for n in names:
            st = self.states.get(n, "")
            speaking = self.levels.get(n, 0) > 0.012
            color = "#ff2e40" if speaking else "#ececf0" if st == "connected" else "#55555e"
            extra = " (mudo)" if n in self.muted else "" if st == "connected" or not on else " (conectando)"
            vol, silent = self.volume(n)
            extra += " [silenciado por voce]" if silent else f" [{vol}%]" if vol != 100 else ""
            text = f'<span style="color:{color}">{"◉" if speaking else "●"} {n}{extra}</span>'
            parts.append(f'<a href="{n}" style="text-decoration:none">{text}</a>' if on else text)
        if on and self.engine.muted:
            parts.append('<span style="color:#ffb347">seu microfone esta mudo</span>')
        if on and self.engine.grabber:
            parts.append('<span style="color:#ffb347">sua tela esta visivel</span>')
        b.people.setText(" &nbsp; ".join(parts) or '<span style="color:#55555e">so voce por enquanto</span>')
        b.set_views(sorted(self.screens), self.view)
