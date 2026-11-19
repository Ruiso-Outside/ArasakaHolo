"""
ARASAKA HOLO // chat (interface PySide6).
"""
from __future__ import annotations

import hashlib
import json
import socket
import sys
import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, QRectF, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QKeySequence, QPainter, QPen, QShortcut
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QFrame,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
                               QMessageBox, QPlainTextEdit, QScrollArea, QSizePolicy, QStackedWidget, QVBoxLayout,
                               QWidget)

from . import crypto, identity
from . import fx
from .kit import (FONTS, LINE, MUTED, RED, BaseDialog, CutFrame, HudHeader, Indicator, button, label, load_fonts,
                  logo_pixmap, spaced, stylesheet)
from .net import HoloClient, normalize_url

APP_NAME = "ARASAKA HOLO"
VERSION = "1.0.1"
ASSETS = Path(__file__).resolve().parent / "assets"
DEFAULT_SERVER = "wss://piphin.online/"   # rede oficial (https://piphin.online/)
LOCAL_SERVER = "ws://127.0.0.1:7077"      # servidor rodando neste PC (CONFIG > INICIAR SERVIDOR)
TTLS = [("sem autodestruicao", 0), ("autodestruir: 30 s", 30), ("autodestruir: 5 min", 300),
        ("autodestruir: 1 h", 3600)]
NICK_COLORS = ["#ff2e40", "#ececf0", "#ff9e64", "#ff6b9c", "#ffb86b", "#8fc1c4", "#c879ff", "#9fd8b0"]

EXTRA_QSS = """
QFrame#side { background: #030304; border-right: 1px solid #1a0507; }
QFrame#members { background: #050506; border-left: 1px solid #16161a; }
QListWidget#chans { background: transparent; border: none; }
QListWidget#chans::item { padding: 8px 10px; border-left: 3px solid transparent; color: #8c8c96; }
QListWidget#chans::item:selected { background: rgba(227,18,31,0.18); border-left: 3px solid #e3121f; color: #ffffff; }
QListWidget#chans::item:hover { background: rgba(227,18,31,0.08); color: #ffffff; }
QPlainTextEdit#composer { background: #050506; border: 1px solid #2a2a31; padding: 8px; }
QPlainTextEdit#composer:focus { border-color: #e3121f; }
QFrame#msg_me { background: #160609; border-left: 3px solid #e3121f; }
QFrame#msg_other { background: #0d0d10; border-left: 3px solid #2a2a31; }
QFrame#msg_warn { background: #1d0a00; border-left: 3px solid #ffb347; }
QFrame#topbar { background: #050506; border-bottom: 1px solid #1a0507; }
"""


def nick_color(nick: str) -> str:
    h = hashlib.blake2b(nick.encode(), digest_size=2).digest()
    return NICK_COLORS[h[0] % len(NICK_COLORS)]


def esc(t: str) -> str:
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def lan_ips() -> list[str]:
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(i for i in ips if not i.startswith("127."))


class Bridge(QObject):
    event = Signal(object)


class Task(QThread):
    done = Signal(object)

    def __init__(self, fn, *a):
        super().__init__()
        self.fn, self.a = fn, a

    def run(self):
        try:
            self.done.emit(self.fn(*self.a))
        except Exception as e:  # noqa: BLE001
            self.done.emit(e)


# ================================================================ estado local
class Store:
    """Configuracoes + chaves publicas fixadas (TOFU local). Nada de mensagens."""

    def __init__(self):
        self.dir = identity.config_dir()
        self.path = self.dir / "settings.json"
        self.data = {"server": DEFAULT_SERVER, "ttl": 0, "remember_rooms": False, "rooms": [], "pins": {}}
        try:
            self.data.update(json.loads(self.path.read_text(encoding="utf-8")))
        except Exception:
            pass

    def save(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=1), encoding="utf-8")

    def pin(self, nick: str, pk: str) -> str:
        """'new' | 'ok' | 'changed'"""
        pins = self.data.setdefault("pins", {})
        old = pins.get(nick)
        if old is None:
            pins[nick] = pk
            self.save()
            return "new"
        return "ok" if old == pk else "changed"


# ================================================================ widgets
class IdentityCard(QWidget):
    def __init__(self, ident: identity.Identity):
        super().__init__()
        self.ident = ident
        self.setFixedHeight(150)
        self.logo = logo_pixmap(34)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = self.width()
        p.drawPixmap(18, 16, self.logo)
        f = QFont(FONTS["brand"])
        f.setPixelSize(20)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 4)
        p.setFont(f)
        p.setPen(QColor(236, 236, 240))
        p.drawText(QRectF(62, 14, w, 22), Qt.AlignLeft | Qt.AlignVCenter, "ARASAKA")
        f2 = QFont(FONTS["ui"])
        f2.setPixelSize(11)
        f2.setBold(True)
        f2.setLetterSpacing(QFont.AbsoluteSpacing, 3)
        p.setFont(f2)
        p.setPen(RED)
        p.drawText(QRectF(63, 36, w - 70, 16), Qt.AlignLeft | Qt.AlignVCenter, "HOLO // SECURE COMMS")
        p.fillRect(QRectF(14, 64, w - 28, 74), QColor(18, 5, 7))
        p.setPen(QPen(QColor(90, 8, 14), 1))
        p.drawRect(QRectF(14, 64, w - 28, 74))
        p.fillRect(QRectF(14, 64, 3, 74), RED)
        f3 = QFont(FONTS["ui"])
        f3.setPixelSize(10)
        f3.setBold(True)
        f3.setLetterSpacing(QFont.AbsoluteSpacing, 3)
        p.setFont(f3)
        p.setPen(MUTED)
        p.drawText(QRectF(26, 68, w, 16), Qt.AlignLeft | Qt.AlignVCenter, "SEU NICK ETERNO")
        f4 = QFont(FONTS["ui"])
        f4.setPixelSize(18)
        f4.setBold(True)
        f4.setLetterSpacing(QFont.AbsoluteSpacing, 1.5)
        p.setFont(f4)
        p.setPen(QColor(255, 255, 255))
        p.drawText(QRectF(26, 84, w - 40, 26), Qt.AlignLeft | Qt.AlignVCenter, self.ident.nick)
        f5 = QFont(FONTS["mono"])
        f5.setPixelSize(10)
        p.setFont(f5)
        p.setPen(QColor(140, 60, 66))
        p.drawText(QRectF(26, 110, w - 40, 22), Qt.AlignLeft | Qt.AlignVCenter, "CHAVE " + self.ident.fp)


class MessageWidget(QFrame):
    expired = Signal(object)

    def __init__(self, body: dict, mine: bool, status: str):
        super().__init__()
        self.setObjectName("msg_warn" if status == "changed" else "msg_me" if mine else "msg_other")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 8, 14, 10)
        lay.setSpacing(3)
        head = QHBoxLayout()
        head.setSpacing(8)
        n = QLabel(esc(body["n"]))
        n.setStyleSheet(f"color: {nick_color(body['n'])}; font-weight: 700;")
        spaced(n, 1)
        head.addWidget(n)
        badge = {"ok": ("✔ verificado", "#8c8c96"), "new": ("✔ chave fixada", "#8c8c96"),
                 "pending": ("… verificando", "#55555e"),
                 "changed": ("⚠ CHAVE DIFERENTE DA CONHECIDA", "#ffb347"),
                 "mismatch": ("⚠ ASSINATURA NAO CONFERE COM O NICK", "#ff2e40")}.get(status, ("", "#55555e"))
        self.badge = QLabel(badge[0])
        self.badge.setStyleSheet(f"color: {badge[1]}; font-size: 11px;")
        head.addWidget(self.badge)
        head.addStretch()
        self.ttl_lbl = QLabel("")
        self.ttl_lbl.setStyleSheet("color: #ff6b7a; font-size: 11px;")
        head.addWidget(self.ttl_lbl)
        t = QLabel(time.strftime("%H:%M", time.localtime(body.get("ts", time.time()))))
        t.setStyleSheet("color: #55555e; font-size: 11px;")
        head.addWidget(t)
        lay.addLayout(head)
        txt = QLabel(esc(body["t"]).replace("\n", "<br>"))
        txt.setTextFormat(Qt.RichText)
        txt.setWordWrap(True)
        txt.setTextInteractionFlags(Qt.TextSelectableByMouse)
        txt.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        txt.setStyleSheet("color: #e6e6ea; font-size: 15px;")
        lay.addWidget(txt)
        self.deadline = 0.0
        ttl = int(body.get("ttl") or 0)
        if ttl > 0:
            self.deadline = time.time() + ttl
            self.timer = QTimer(self)
            self.timer.timeout.connect(self._tick)
            self.timer.start(1000)
            self._tick()

    def set_status(self, status: str):
        if status in ("ok", "new"):
            self.badge.setText("✔ verificado")
            self.badge.setStyleSheet("color: #8c8c96; font-size: 11px;")
        elif status == "mismatch":
            self.badge.setText("⚠ ASSINATURA NAO CONFERE COM O NICK")
            self.badge.setStyleSheet("color: #ff2e40; font-size: 11px;")

    def _tick(self):
        left = int(self.deadline - time.time())
        if left <= 0:
            self.timer.stop()
            self.expired.emit(self)
            return
        self.ttl_lbl.setText(f"⌛ {left // 60}:{left % 60:02d}" if left >= 60 else f"⌛ {left}s")


class ChatView(QScrollArea):
    MAX = 400

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        inner.setObjectName("page")
        self.lay = QVBoxLayout(inner)
        self.lay.setContentsMargins(24, 16, 24, 16)
        self.lay.setSpacing(8)
        self.lay.addStretch()
        self.setWidget(inner)
        self.by_id: dict[str, MessageWidget] = {}

    def _append(self, w: QWidget):
        self.lay.addWidget(w)
        while self.lay.count() - 1 > self.MAX:
            old = self.lay.takeAt(1).widget()
            if old:
                old.deleteLater()
        QTimer.singleShot(30, lambda: self.verticalScrollBar().setValue(self.verticalScrollBar().maximum()))

    def add_message(self, body: dict, mine: bool, status: str) -> MessageWidget:
        w = MessageWidget(body, mine, status)
        w.expired.connect(self._expire)
        self.by_id[body.get("id", str(id(w)))] = w
        self._append(w)
        return w

    def add_system(self, text: str, color: str = "#55555e"):
        lb = QLabel(f"— {esc(text)} —")
        lb.setAlignment(Qt.AlignCenter)
        lb.setWordWrap(True)
        lb.setStyleSheet(f"color: {color}; font-size: 12px; padding: 4px;")
        self._append(lb)

    def _expire(self, w):
        w.setVisible(False)
        w.deleteLater()

    def clear_all(self):
        while self.lay.count() > 1:
            it = self.lay.takeAt(1)
            if it.widget():
                it.widget().deleteLater()
        self.by_id.clear()


class Channel:
    def __init__(self, kind: str, title: str, key: bytes | None = None, peer: str = "", peer_pk: str = "",
                 locked: bool = False):
        self.kind, self.title, self.key, self.peer, self.peer_pk, self.locked = kind, title, key, peer, peer_pk, locked
        self.rid = crypto.room_id(key) if key else ""
        self.view = ChatView()
        self.members: set[str] = set()
        self.unread = 0
        self.item: QListWidgetItem | None = None

    @property
    def cid(self) -> str:
        return ("room:" + self.rid) if self.kind == "room" else ("dm:" + self.peer)


# ================================================================ dialogos
class JoinDialog(BaseDialog):
    def __init__(self, parent):
        super().__init__(parent, "ENTRAR EM SALA", "Criptografia ponta a ponta com chave derivada da senha")
        f = QFormLayout()
        self.name = QLineEdit("lobby")
        f.addRow(label("SALA", "muted", 2, bold=True), self.name)
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setPlaceholderText("opcional")
        f.addRow(label("SENHA", "muted", 2, bold=True), self.pw)
        self.lay.addLayout(f)
        self.lay.addWidget(label("Sem senha, a sala e publica: quem souber o nome consegue ler. Com senha, so quem "
                                 "tiver a senha le, e nem o servidor sabe o nome da sala.", "muted", 0.3, wrap=True))
        self.add_buttons("ENTRAR")


class DmDialog(BaseDialog):
    def __init__(self, parent):
        super().__init__(parent, "MENSAGEM DIRETA", "So o destinatario consegue ler")
        self.nick = QLineEdit()
        self.nick.setPlaceholderText("ex.: KuroiRonin-7F3A")
        self.lay.addWidget(self.nick)
        self.lay.addWidget(label("Confira a impressao digital da chave com a pessoa por outro meio na primeira vez. "
                                 "Ela aparece no painel da direita.", "muted", 0.3, wrap=True))
        self.add_buttons("ABRIR CONVERSA")


class SettingsDialog(BaseDialog):
    def __init__(self, win: "MainWindow"):
        super().__init__(win, "CONFIGURACOES", "Servidor, identidade e privacidade")
        self.win = win
        s = win.store.data
        f = QFormLayout()
        f.setSpacing(10)
        self.server = QLineEdit(s["server"])
        self.server.setPlaceholderText("ws://ip:7077  ou  wss://dominio")
        f.addRow(label("SERVIDOR", "muted", 2, bold=True), self.server)
        self.remember = QCheckBox("Lembrar as salas neste computador (salva nome e senha em disco)")
        self.remember.setChecked(bool(s.get("remember_rooms")))
        f.addRow("", self.remember)
        self.lay.addLayout(f)
        host = CutFrame(cut=10)
        hl = QVBoxLayout(host)
        hl.setContentsMargins(16, 12, 16, 12)
        hl.addWidget(label("HOSPEDAR SERVIDOR NESTE PC", "section", 3))
        ips = lan_ips()
        hl.addWidget(label("Roda o relay cego aqui (porta 7077). Na mesma rede, seus amigos usam:  " +
                           ("  ·  ".join(f"ws://{i}:7077" for i in ips) or "ws://SEU-IP:7077"), "muted", 0.3,
                           wrap=True))
        row = QHBoxLayout()
        self.host_btn = button("PARAR SERVIDOR" if win.hosting else "INICIAR SERVIDOR",
                               "danger" if win.hosting else "primary", self.toggle_host)
        row.addWidget(self.host_btn)
        row.addStretch()
        hl.addLayout(row)
        self.lay.addWidget(host)
        idf = CutFrame(cut=10)
        il = QVBoxLayout(idf)
        il.setContentsMargins(16, 12, 16, 12)
        il.addWidget(label("IDENTIDADE", "section", 3))
        il.addWidget(label(f"{win.ident.nick}  ·  origem: {win.ident.source}", None, 0.5, bold=True))
        il.addWidget(label("O nick vem do MAC da placa de rede (o MAC nunca sai do computador). A posse do nick e "
                           "provada pela sua chave: faca um backup para manter o nick depois de reinstalar.",
                           "muted", 0.3, wrap=True))
        r2 = QHBoxLayout()
        r2.addWidget(button("EXPORTAR CHAVE", None, self.export))
        r2.addWidget(button("IMPORTAR CHAVE", None, self.import_))
        r2.addStretch()
        il.addLayout(r2)
        self.lay.addWidget(idf)
        self.add_buttons("SALVAR")

    def toggle_host(self):
        self.win.toggle_host()
        self.host_btn.setText("PARAR SERVIDOR" if self.win.hosting else "INICIAR SERVIDOR")

    def export(self):
        p, _ = QFileDialog.getSaveFileName(self, "Exportar chave", str(Path.home() / f"{self.win.ident.nick}.holo"),
                                           "Identidade HOLO (*.holo)")
        if p:
            Path(p).write_text(self.win.ident.export(), encoding="utf-8")
            QMessageBox.information(self, "Exportado", "Guarde esse arquivo em lugar seguro: quem tiver ele pode "
                                                       "falar como voce.")

    def import_(self):
        p, _ = QFileDialog.getOpenFileName(self, "Importar chave", str(Path.home()), "Identidade HOLO (*.holo)")
        if p:
            try:
                identity.import_identity(Path(p).read_text(encoding="utf-8"))
                QMessageBox.information(self, "Importado", "Chave importada. Reabra o HOLO.")
            except Exception as e:  # noqa: BLE001
                QMessageBox.warning(self, "Erro", str(e))


# ================================================================ janela
class MainWindow(QMainWindow):
    def __init__(self, ident: identity.Identity, store: Store):
        super().__init__()
        self.ident, self.store = ident, store
        self.channels: dict[str, Channel] = {}
        self.current: Channel | None = None
        self.directory: dict[str, str | None] = {}       # nick -> pk (respostas whois)
        self.pending_verify: dict[str, list] = {}
        self.pending_dm: dict[str, Channel] = {}
        self.tasks: list[Task] = []
        self.hosting = False
        self.host_stop = None
        self.host_loop = None
        self.setWindowTitle(f"{APP_NAME} — {ident.nick}")
        self.setWindowIcon(QIcon(str(ASSETS / "arasaka-holo.svg")))
        self.resize(1260, 820)
        self.setMinimumSize(980, 620)

        root = QWidget()
        root.setObjectName("root")
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        # ---------------------------------------------------- lateral
        side = QFrame()
        side.setObjectName("side")
        side.setFixedWidth(270)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 10)
        sl.setSpacing(4)
        sl.addWidget(IdentityCard(ident))
        st = QHBoxLayout()
        st.setContentsMargins(16, 0, 16, 0)
        self.ind = Indicator(False)
        st.addWidget(self.ind)
        self.state_lbl = label("CONECTANDO...", "muted", 2, 11, True)
        st.addWidget(self.state_lbl, 1)
        sl.addLayout(st)
        sl.addSpacing(8)
        rh = QHBoxLayout()
        rh.setContentsMargins(16, 0, 10, 0)
        rh.addWidget(label("SALAS", "section", 3), 1)
        b = button("+", "ghost", self.join_dialog, "Entrar em sala (Ctrl+J)")
        b.setFixedWidth(34)
        rh.addWidget(b)
        sl.addLayout(rh)
        self.rooms_list = QListWidget()
        self.rooms_list.setObjectName("chans")
        self.rooms_list.itemClicked.connect(self.select_item)
        sl.addWidget(self.rooms_list, 2)
        dh = QHBoxLayout()
        dh.setContentsMargins(16, 0, 10, 0)
        dh.addWidget(label("DIRETAS", "section", 3), 1)
        b = button("+", "ghost", self.dm_dialog, "Nova mensagem direta (Ctrl+D)")
        b.setFixedWidth(34)
        dh.addWidget(b)
        sl.addLayout(dh)
        self.dm_list = QListWidget()
        self.dm_list.setObjectName("chans")
        self.dm_list.itemClicked.connect(self.select_item)
        sl.addWidget(self.dm_list, 1)
        foot = QHBoxLayout()
        foot.setContentsMargins(12, 0, 12, 0)
        foot.addWidget(button("CONFIG", "ghost", self.settings_dialog))
        foot.addStretch()
        foot.addWidget(button("PANICO", "danger", self.panic, "Apaga tudo da tela e sai das salas (Ctrl+Shift+X)"))
        sl.addLayout(foot)
        h.addWidget(side)

        # ---------------------------------------------------- centro
        center = QWidget()
        cl = QVBoxLayout(center)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        top = QFrame()
        top.setObjectName("topbar")
        tl = QHBoxLayout(top)
        tl.setContentsMargins(22, 12, 22, 12)
        self.title = label("", None, 3, 18, True)
        tl.addWidget(self.title)
        self.lock = label("", "red", 2, 11, True)
        tl.addWidget(self.lock)
        tl.addStretch()
        self.e2e = label("■ PONTA A PONTA  ·  SERVIDOR CEGO  ·  SEM HISTORICO", "muted", 2, 11, True)
        tl.addWidget(self.e2e)
        cl.addWidget(top)
        self.stack = QStackedWidget()
        self.welcome = self.build_welcome()
        self.stack.addWidget(self.welcome)
        cl.addWidget(self.stack, 1)
        comp = QFrame()
        comp.setObjectName("topbar")
        col = QVBoxLayout(comp)
        col.setContentsMargins(22, 10, 22, 12)
        self.input = QPlainTextEdit()
        self.input.setObjectName("composer")
        self.input.setPlaceholderText("mensagem cifrada...  (Enter envia · Shift+Enter quebra linha)")
        self.input.setFixedHeight(76)
        self.input.installEventFilter(self)
        col.addWidget(self.input)
        row = QHBoxLayout()
        self.ttl = QComboBox()
        for t, v in TTLS:
            self.ttl.addItem(t, v)
        self.ttl.setCurrentIndex(max(0, [v for _t, v in TTLS].index(store.data.get("ttl", 0))
                                     if store.data.get("ttl", 0) in [v for _t, v in TTLS] else 0))
        self.ttl.currentIndexChanged.connect(lambda _i: self._save_ttl())
        row.addWidget(self.ttl)
        row.addStretch()
        self.counter = label("", "dim", 0.5, 11)
        row.addWidget(self.counter)
        self.send_btn = button("ENVIAR  ▶", "primary", self.send)
        row.addWidget(self.send_btn)
        col.addLayout(row)
        self.input.textChanged.connect(lambda: self.counter.setText(
            f"{len(self.input.toPlainText())}/{crypto.MAX_TEXT}"))
        cl.addWidget(comp)
        self.composer = comp
        h.addWidget(center, 1)

        # ---------------------------------------------------- membros / contato
        mem = QFrame()
        mem.setObjectName("members")
        mem.setFixedWidth(240)
        ml = QVBoxLayout(mem)
        ml.setContentsMargins(14, 14, 14, 14)
        self.side_title = label("ONLINE", "section", 3)
        ml.addWidget(self.side_title)
        self.members = QListWidget()
        self.members.setObjectName("chans")
        self.members.itemDoubleClicked.connect(lambda it: self.open_dm(it.data(Qt.UserRole)))
        ml.addWidget(self.members, 1)
        self.peer_info = label("", "muted", 0.3, 12, wrap=True)
        ml.addWidget(self.peer_info)
        ml.addWidget(label("Duplo clique num nick abre uma mensagem direta.", "dim", 0.3, 11, wrap=True))
        h.addWidget(mem)
        self.setCentralWidget(root)
        self.composer.setEnabled(False)

        QShortcut(QKeySequence("Ctrl+J"), self, self.join_dialog)
        QShortcut(QKeySequence("Ctrl+D"), self, self.dm_dialog)
        QShortcut(QKeySequence("Ctrl+Shift+X"), self, self.panic)

        # ---------------------------------------------------- rede
        self.bridge = Bridge()
        self.bridge.event.connect(self.on_event)
        self.client: HoloClient | None = None
        self.connect_server()
        if store.data.get("remember_rooms"):
            for r in store.data.get("rooms", []):
                self.join_room(r["name"], r.get("pw", ""))

    # ------------------------------------------------------------ ui util
    def build_welcome(self) -> QWidget:
        w = QWidget()
        w.setObjectName("page")
        l = QVBoxLayout(w)
        l.setContentsMargins(60, 40, 60, 40)
        l.addStretch()
        lg = QLabel()
        lg.setPixmap(logo_pixmap(110))
        lg.setAlignment(Qt.AlignCenter)
        l.addWidget(lg)
        t = label("CANAL SEGURO", None, 6, 26, True)
        t.setAlignment(Qt.AlignCenter)
        l.addWidget(t)
        for line in ["Sem conta. Sem login. Sem e-mail. Sem telefone.",
                     f"Voce e  {self.ident.nick}  para sempre neste computador.",
                     "Mensagens cifradas no seu PC: o servidor so repassa blobs e nao guarda nada.",
                     "Quem estiver offline nao recebe: nao existe historico em lugar nenhum."]:
            x = label(line, "muted", 0.5, 14)
            x.setAlignment(Qt.AlignCenter)
            l.addWidget(x)
        l.addSpacing(14)
        r = QHBoxLayout()
        r.addStretch()
        r.addWidget(button("ENTRAR NO LOBBY", "primary", lambda: self.join_room("lobby", "")))
        r.addWidget(button("SALA PRIVADA", None, self.join_dialog))
        r.addWidget(button("MENSAGEM DIRETA", None, self.dm_dialog))
        r.addStretch()
        l.addLayout(r)
        l.addStretch()
        return w

    def toast(self, text: str, color="#ff2e40"):
        if self.current:
            self.current.view.add_system(text, color)
        else:
            self.statusBar().showMessage(text, 5000)

    def _save_ttl(self):
        self.store.data["ttl"] = self.ttl.currentData()
        self.store.save()

    def eventFilter(self, obj, e):
        if obj is self.input and e.type() == e.Type.KeyPress and e.key() in (Qt.Key_Return, Qt.Key_Enter) \
                and not e.modifiers() & Qt.ShiftModifier:
            self.send()
            return True
        return False

    # ------------------------------------------------------------ conexao
    def connect_server(self):
        if self.client:
            self.client.stop()
        self.client = HoloClient(self.store.data["server"], self.ident, self.bridge.event.emit)
        for ch in self.channels.values():
            if ch.kind == "room":
                self.client.rooms.add(ch.rid)
        self.client.start()

    def on_event(self, m: dict):
        op = m.get("op")
        if op == "_state":
            st = m["state"]
            self.ind.set_ok(st == "online")
            txt = {"connecting": "CONECTANDO...", "online": "ONLINE", "offline": "OFFLINE · RECONECTANDO",
                   "stopped": "DESCONECTADO"}.get(st, st.upper())
            self.state_lbl.setText(txt)
            self.state_lbl.setToolTip(m.get("error", "") or m.get("url", ""))
            # mostra o motivo uma vez por motivo (sem repetir a cada nova tentativa)
            err = m.get("error", "")
            if st == "offline" and err and err != getattr(self, "_last_net_error", ""):
                self._last_net_error = err
                self.toast("sem conexao: " + err)
            elif st == "online":
                self._last_net_error = ""
        elif op == "welcome":
            self.state_lbl.setText(f"ONLINE · {m.get('online', 1)} NICK(S)")
            self.state_lbl.setToolTip(self.store.data["server"])
            if m.get("new"):
                self.toast(f"nick {self.ident.nick} registrado e vinculado a sua chave", "#ececf0")
            if m.get("motd"):
                self.toast("servidor: " + m["motd"], "#8c8c96")
        elif op == "error":
            code = m.get("code")
            if code == "nick_taken":
                QMessageBox.critical(self, "NICK JA VINCULADO",
                                     f"O nick {self.ident.nick} ja foi registrado neste servidor com outra chave.\n\n"
                                     "Se e voce (reinstalou o sistema), importe o backup da chave em CONFIG.\n"
                                     "Se nao, outra pessoa reivindicou esse nick primeiro.")
            elif code == "offline":
                ch = self.channels.get("dm:" + m.get("to", "")) or self.current
                if ch:
                    ch.view.add_system(m.get("msg", "offline"), "#ffb347")
            else:
                self.toast(m.get("msg", code or "erro"))
        elif op == "joined":
            ch = self.room_by_rid(m["room"])
            if ch:
                ch.members = set(m.get("members", []))
                self.refresh_members()
        elif op == "presence":
            ch = self.room_by_rid(m["room"])
            if ch:
                (ch.members.add if m["on"] else ch.members.discard)(m["nick"])
                ch.view.add_system(f"{m['nick']} {'entrou' if m['on'] else 'saiu'}", "#55555e")
                self.refresh_members()
        elif op == "msg":
            self.on_room_msg(m)
        elif op == "dm":
            self.on_dm(m)
        elif op == "whois":
            self.on_whois(m)

    def room_by_rid(self, rid: str) -> Channel | None:
        return self.channels.get("room:" + rid)

    # ------------------------------------------------------------ verificacao de remetente
    def verify_sender(self, body: dict) -> str:
        """Confere se a chave que assinou e a chave do nick (diretorio + chave fixada localmente)."""
        nick, k = body["n"], body["k"]
        if nick == self.ident.nick:
            return "ok" if k == self.ident.pk_b64 else "mismatch"
        known = self.directory.get(nick, "?")
        if known == "?":
            self.client.send({"op": "whois", "nick": nick})
            return "pending"
        if known != k:
            return "mismatch"
        return self.store.pin(nick, k)

    def on_whois(self, m: dict):
        nick, pk = m["nick"], m.get("pk")
        self.directory[nick] = pk
        for body, w in self.pending_verify.pop(nick, []):
            try:
                w.set_status("mismatch" if pk != body["k"] else ("ok" if self.store.pin(nick, pk) != "changed"
                                                                  else "mismatch"))
            except RuntimeError:
                pass
        ch = self.pending_dm.pop(nick, None)
        if ch:
            if not pk:
                ch.view.add_system(f"{nick} nao existe neste servidor", "#ff2e40")
            else:
                ch.peer_pk = pk
                pin = self.store.pin(nick, pk)
                if pin == "changed":
                    ch.view.add_system(f"ATENCAO: a chave de {nick} mudou desde a ultima conversa. Pode ser outra "
                                       "pessoa ou um servidor malicioso.", "#ffb347")
                ch.view.add_system(f"chave de {nick}: {identity.fingerprint(crypto.ub64(pk))}  ·  "
                                   f"{'online' if m.get('online') else 'offline'}", "#8c8c96")
            if ch is self.current:
                self.refresh_members()

    # ------------------------------------------------------------ salas
    def join_dialog(self):
        d = JoinDialog(self)
        if d.exec() == QDialog.Accepted and d.name.text().strip():
            self.join_room(d.name.text().strip(), d.pw.text())

    def join_room(self, name: str, pw: str):
        name = name.strip().lstrip("#")[:48]
        self.toast("derivando chave da sala (Argon2id)...", "#55555e")
        t = Task(crypto.room_key, name, pw)

        def done(key):
            if isinstance(key, Exception):
                return self.toast(f"erro: {key}")
            ch = Channel("room", name, key, locked=bool(pw))
            if ch.cid in self.channels:
                return self.select_channel(self.channels[ch.cid])
            self.channels[ch.cid] = ch
            self.stack.addWidget(ch.view)
            ch.item = QListWidgetItem(("🔒 " if pw else "#  ") + name)
            ch.item.setData(Qt.UserRole, ch.cid)
            self.rooms_list.addItem(ch.item)
            ch.view.add_system(f"sala {name} · id para o servidor: {ch.rid[:12]}… · "
                               + ("protegida por senha" if pw else "publica (sem senha)"), "#8c8c96")
            self.client.send({"op": "join", "room": ch.rid})
            if self.store.data.get("remember_rooms"):
                rooms = [r for r in self.store.data.get("rooms", []) if r["name"] != name]
                self.store.data["rooms"] = rooms + [{"name": name, "pw": pw}]
                self.store.save()
            self.select_channel(ch)
        t.done.connect(done)
        self.tasks = [x for x in self.tasks if x.isRunning()] + [t]
        t.start()

    def on_room_msg(self, m: dict):
        ch = self.room_by_rid(m["room"])
        if not ch:
            return
        body = crypto.open_room(ch.key, m["blob"])
        if not body:
            return ch.view.add_system("mensagem que nao abre com esta chave (descartada)", "#ffb347")
        status = self.verify_sender(body)
        w = ch.view.add_message(body, body["n"] == self.ident.nick, status)
        if status == "pending":
            self.pending_verify.setdefault(body["n"], []).append((body, w))
        self.bump(ch)

    # ------------------------------------------------------------ diretas
    def dm_dialog(self):
        d = DmDialog(self)
        if d.exec() == QDialog.Accepted and d.nick.text().strip():
            self.open_dm(d.nick.text().strip())

    def open_dm(self, nick: str):
        if not nick or nick == self.ident.nick:
            return
        cid = "dm:" + nick
        ch = self.channels.get(cid)
        if not ch:
            ch = Channel("dm", nick, peer=nick)
            self.channels[cid] = ch
            self.stack.addWidget(ch.view)
            ch.item = QListWidgetItem("@  " + nick)
            ch.item.setData(Qt.UserRole, cid)
            self.dm_list.addItem(ch.item)
            ch.view.add_system(f"conversa direta com {nick} · cifrada so para voces dois · nada fica salvo",
                               "#8c8c96")
            self.pending_dm[nick] = ch
            self.client.send({"op": "whois", "nick": nick})
        self.select_channel(ch)

    def on_dm(self, m: dict):
        frm, pk = m.get("from", ""), m.get("from_pk", "")
        pin = self.store.pin(frm, pk)
        body = crypto.open_dm(self.ident.sk, pk, m["blob"])
        cid = "dm:" + frm
        if cid not in self.channels:
            ch = Channel("dm", frm, peer=frm, peer_pk=pk)
            self.channels[cid] = ch
            self.stack.addWidget(ch.view)
            ch.item = QListWidgetItem("@  " + frm)
            ch.item.setData(Qt.UserRole, cid)
            self.dm_list.addItem(ch.item)
            ch.view.add_system(f"{frm} abriu uma conversa direta · chave {identity.fingerprint(crypto.ub64(pk))}",
                               "#8c8c96")
        ch = self.channels[cid]
        ch.peer_pk = ch.peer_pk or pk
        if not body or body.get("n") != frm:
            return ch.view.add_system("mensagem direta invalida descartada", "#ffb347")
        if pin == "changed":
            ch.view.add_system(f"ATENCAO: a chave de {frm} mudou. Confirme com a pessoa por outro meio.", "#ffb347")
        ch.view.add_message(body, False, "changed" if pin == "changed" else "ok")
        self.bump(ch)

    # ------------------------------------------------------------ envio
    def send(self):
        ch = self.current
        text = self.input.toPlainText().strip()
        if not ch or not text:
            return
        if len(text) > crypto.MAX_TEXT:
            return self.toast(f"mensagem maior que {crypto.MAX_TEXT} caracteres")
        if not self.client or not self.client.connected:
            return self.toast("sem conexao com o servidor")
        ttl = int(self.ttl.currentData() or 0)
        if ch.kind == "room":
            self.client.send({"op": "msg", "room": ch.rid,
                              "blob": crypto.seal_room(ch.key, self.ident.sk, self.ident.nick, text, ttl)})
        else:
            if not ch.peer_pk:
                return self.toast("ainda buscando a chave do destinatario...")
            blob = crypto.seal_dm(self.ident.sk, self.ident.nick, ch.peer_pk, text, ttl, ch.peer)
            self.client.send({"op": "dm", "to": ch.peer, "blob": blob})
            body = {"n": self.ident.nick, "k": self.ident.pk_b64, "t": text, "ts": int(time.time()), "ttl": ttl}
            ch.view.add_message(body, True, "ok")
        self.input.clear()

    # ------------------------------------------------------------ navegacao
    def select_item(self, it: QListWidgetItem):
        ch = self.channels.get(it.data(Qt.UserRole))
        if ch:
            self.select_channel(ch)

    def select_channel(self, ch: Channel):
        self.current = ch
        ch.unread = 0
        self.update_item(ch)
        self.stack.setCurrentWidget(ch.view)
        self.title.setText(("#" if ch.kind == "room" else "@") + ch.title.upper())
        self.lock.setText("■ SENHA" if ch.locked else ("■ PUBLICA" if ch.kind == "room" else "■ DIRETA"))
        self.composer.setEnabled(True)
        (self.rooms_list if ch.kind == "room" else self.dm_list).setCurrentItem(ch.item)
        (self.dm_list if ch.kind == "room" else self.rooms_list).clearSelection()
        self.refresh_members()
        self.input.setFocus()

    def bump(self, ch: Channel):
        if ch is not self.current or not self.isActiveWindow():
            ch.unread += 1
            self.update_item(ch)
            QApplication.alert(self, 0)

    def update_item(self, ch: Channel):
        if ch.item:
            base = (("🔒 " if ch.locked else "#  ") if ch.kind == "room" else "@  ") + ch.title
            ch.item.setText(base + (f"   ({ch.unread})" if ch.unread else ""))

    def refresh_members(self):
        self.members.clear()
        ch = self.current
        if not ch:
            return
        if ch.kind == "room":
            self.side_title.setText(f"ONLINE  ·  {len(ch.members)}")
            for n in sorted(ch.members):
                it = QListWidgetItem(("◆ " if n == self.ident.nick else "● ") + n)
                it.setData(Qt.UserRole, n)
                it.setForeground(QColor(nick_color(n)))
                self.members.addItem(it)
            self.peer_info.setText("O servidor ve quantos nicks estao na sala, mas nao o nome dela nem as "
                                   "mensagens.")
        else:
            self.side_title.setText("CONTATO")
            it = QListWidgetItem("● " + ch.peer)
            it.setForeground(QColor(nick_color(ch.peer)))
            self.members.addItem(it)
            fp = identity.fingerprint(crypto.ub64(ch.peer_pk)) if ch.peer_pk else "buscando..."
            self.peer_info.setText(f"IMPRESSAO DIGITAL\n{fp}\n\nConfira com a pessoa por outro meio. Se mudar, "
                                   "o HOLO avisa.")

    # ------------------------------------------------------------ extras
    def settings_dialog(self):
        d = SettingsDialog(self)
        if d.exec() == QDialog.Accepted:
            changed = normalize_url(d.server.text()) != self.store.data["server"]
            self.store.data["server"] = normalize_url(d.server.text()) or DEFAULT_SERVER
            self.store.data["remember_rooms"] = d.remember.isChecked()
            if not d.remember.isChecked():
                self.store.data["rooms"] = []
            self.store.save()
            if changed:
                self.connect_server()

    def toggle_host(self):
        if self.hosting:
            if self.host_loop and self.host_stop:
                self.host_loop.call_soon_threadsafe(self.host_stop.set)
            self.hosting = False
            return
        import asyncio
        from . import server
        ready = threading.Event()

        def run():
            self.host_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.host_loop)
            self.host_stop = asyncio.Event()
            try:
                self.host_loop.run_until_complete(server.serve("0.0.0.0", 7077, server.default_data_dir(),
                                                               quiet=True, stop=self.host_stop, ready=ready.set))
            except OSError as e:
                self.bridge.event.emit({"op": "error", "code": "host", "msg": f"servidor local: {e}"})
                ready.set()
        threading.Thread(target=run, daemon=True).start()
        ready.wait(5)
        self.hosting = True
        if self.store.data["server"] != LOCAL_SERVER:
            self.store.data["server"] = LOCAL_SERVER
            self.store.save()
            self.connect_server()

    def panic(self):
        for ch in list(self.channels.values()):
            if ch.kind == "room" and self.client:
                self.client.send({"op": "leave", "room": ch.rid})
            ch.view.clear_all()
            self.stack.removeWidget(ch.view)
            ch.view.deleteLater()
        self.channels.clear()
        self.rooms_list.clear()
        self.dm_list.clear()
        self.members.clear()
        self.current = None
        self.input.clear()
        self.composer.setEnabled(False)
        self.title.setText("")
        self.lock.setText("")
        self.stack.setCurrentWidget(self.welcome)
        QApplication.clipboard().clear()
        self.statusBar().showMessage("PANICO: tudo apagado da memoria e da tela", 4000)

    def closeEvent(self, e):
        if self.client:
            self.client.stop()
        e.accept()


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    QApplication.setApplicationName("arasaka-holo")
    QApplication.setApplicationDisplayName(APP_NAME)
    QApplication.setDesktopFileName("arasaka-holo")
    app = QApplication(argv)
    load_fonts()
    app.setStyleSheet(stylesheet() + EXTRA_QSS)
    app.setWindowIcon(QIcon(str(ASSETS / "arasaka-holo.svg")))
    store = Store()
    srv = next((a.split("=", 1)[1] for a in argv if a.startswith("--server=")), None)
    if srv:
        store.data["server"] = srv
    ident = identity.load_identity()
    win = MainWindow(ident, store)
    # visual Cyberpunk (CRT, glitch, inicialização, barra de status); sem a tela de inicialização nas prévias
    fx.install(win, name="ARASAKA HOLO", icon=ASSETS / "arasaka-holo.svg", extra=lambda: [("NET", win.state_lbl.text())], boot=not any(a.startswith("--screenshot=") for a in argv))
    win.show()
    shot = next((a.split("=", 1)[1] for a in argv if a.startswith("--screenshot=")), None)
    if shot:
        QTimer.singleShot(int(next((a.split("=", 1)[1] for a in argv if a.startswith("--delay=")), "3000")),
                          lambda: (win.grab().save(shot), app.quit()))
    return app.exec()
