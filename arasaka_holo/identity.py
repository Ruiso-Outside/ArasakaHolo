"""
ARASAKA HOLO // identidade.

Nick eterno derivado do MAC da placa de rede fisica:

    MAC (nunca sai do computador)
      -> scrypt(MAC, sal fixo do HOLO)       hash lento: dificulta voltar do nick ao MAC
      -> 32 bytes -> palavra + palavra + 4 hex  ex.: "KuroiRonin-7F3A"

O MAC so decide o nick na PRIMEIRA vez. Depois disso vale a identidade salva: trocar a placa de rede nao muda o
nick, e uma chave existente nunca e sobrescrita (a anterior vira um arquivo identity-*.key na mesma pasta).

O MAC e publico na rede local, entao ele NAO serve como senha. A posse do
nick e provada por uma chave Ed25519 gerada aleatoriamente neste computador
(guardada em ~/.config/arasaka-holo/identity.key). O servidor associa
nick -> chave publica na primeira conexao (TOFU) e nunca mais aceita outra.
Faca backup da chave (Configuracoes > Exportar identidade) para manter o
nick depois de reinstalar o sistema.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from nacl import pwhash
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

APP_ID = "arasaka-holo"
NICK_SALT = b"ARASAKA//HOLO//NICK//v1"

ADJ = ("Kuroi Akai Shiro Neon Chrome Silent Ghost Iron Steel Crimson Void Static Hollow Vapor Razor Night Cyber "
       "Black Red Pale Sharp Cold Burnt Toxic Rogue Phantom Shadow Lunar Solar Quantum Hex Prime Feral Lucid Mute "
       "Grim Noir Rapid Zero Blind Arc Nova Echo Glitch Iso Fused Molten Frozen Wired Spectral Atomic Obsidian "
       "Scarlet Azure Onyx Ashen Ivory Rusted Electric Hyper Ultra Omega Delta Sigma Mirage").split()
NOUN = ("Ronin Oni Samurai Kitsune Tengu Shogun Ninja Daemon Netrunner Fixer Solo Nomad Techie Medic Corpo Ripper "
        "Wraith Specter Raven Viper Cobra Mantis Hornet Falcon Wolf Tiger Dragon Kraken Golem Cipher Vector Pulse "
        "Signal Circuit Kernel Socket Proxy Router Beacon Sentinel Warden Hunter Drifter Runner Phantom Reaper "
        "Monk Blade Katana Shuriken Lotus Sakura Koi Crane Moth Spider Hydra Titan Atlas Orion Vega Lynx").split()


# ================================================================ MAC
@dataclass
class Nic:
    name: str
    mac: str          # "aa:bb:cc:dd:ee:ff"
    wired: bool
    permanent: bool   # endereco de fabrica


def _norm(mac: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def _usable(mac: str) -> bool:
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    first = int(mac[:2], 16)
    # bit 0x02 = endereco "administrado localmente" (MAC aleatorio / virtual); 0x01 = multicast
    return not (first & 0x02) and not (first & 0x01)


VIRTUAL = re.compile(r"virtual|vmware|virtualbox|hyper-v|vethernet|tap|tun|wintun|wireguard|vpn|bluetooth|"
                     r"loopback|docker|wsl|npcap|zerotier|tailscale|hamachi|teredo|isatap|kernel debug", re.I)


def _linux_nics() -> list[Nic]:
    out = []
    base = Path("/sys/class/net")
    if not base.is_dir():
        return out
    for dev in sorted(base.iterdir()):
        name = dev.name
        if name == "lo" or not (dev / "device").exists():       # sem 'device' = interface virtual
            continue
        if re.match(r"(veth|docker|br-|virbr|vmnet|vboxnet|tun|tap|wg|zt|tailscale)", name):
            continue
        mac = ""
        if shutil_which("ethtool"):
            try:
                r = subprocess.run(["ethtool", "-P", name], capture_output=True, text=True, timeout=3)
                mac = _norm(r.stdout.split(":", 1)[-1]) if "Permanent" in r.stdout else ""
            except Exception:
                mac = ""
        permanent = bool(mac)
        if not mac:
            try:
                mac = _norm((dev / "address").read_text())
            except OSError:
                continue
        wireless = (dev / "wireless").exists() or (dev / "phy80211").exists()
        out.append(Nic(name, mac, not wireless, permanent))
    return out


def _windows_nics() -> list[Nic]:
    out = []
    try:
        ps = ("Get-NetAdapter -Physical | Select-Object Name,InterfaceDescription,MacAddress,PermanentAddress,"
              "MediaType | ConvertTo-Json -Compress")
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        data = json.loads(r.stdout or "[]")
        if isinstance(data, dict):
            data = [data]
        for a in data:
            desc = f"{a.get('Name', '')} {a.get('InterfaceDescription', '')}"
            if VIRTUAL.search(desc):
                continue
            perm = _norm(a.get("PermanentAddress") or "")
            mac = perm or _norm(a.get("MacAddress") or "")
            wired = "802.3" in str(a.get("MediaType", "")) and not re.search(r"wi-?fi|wireless|802\.11", desc, re.I)
            out.append(Nic(a.get("Name", "?"), mac, wired, bool(perm)))
    except Exception:
        pass
    if not out:   # fallback: getmac
        try:
            r = subprocess.run(["getmac", "/v", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=10,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in r.stdout.splitlines():
                cols = [c.strip('"') for c in line.split('","')]
                if len(cols) >= 3 and not VIRTUAL.search(cols[0] + cols[1]):
                    out.append(Nic(cols[0], _norm(cols[2]), not re.search(r"wi-?fi|wireless", cols[1], re.I),
                                   False))
        except Exception:
            pass
    return out


def shutil_which(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None


def find_nics() -> list[Nic]:
    nics = _windows_nics() if sys.platform == "win32" else _linux_nics()
    return [n for n in nics if _usable(n.mac)]


def pick_mac() -> tuple[str, str]:
    """Escolhe o MAC de forma deterministica. Retorna (mac, descricao)."""
    override = os.environ.get("ARASAKA_HOLO_MAC")   # apenas para testes
    if override:
        return _norm(override), "override (teste)"
    nics = find_nics()
    if not nics:
        return "", "nenhuma placa de rede fisica encontrada"
    # regra fixa: cabeada primeiro, depois endereco de fabrica, depois o menor MAC
    nics.sort(key=lambda n: (not n.wired, not n.permanent, n.mac))
    n = nics[0]
    return n.mac, n.name


def nick_from_mac(mac: str) -> str:
    raw = bytes.fromhex(mac.replace(":", ""))
    d = hashlib.scrypt(raw, salt=NICK_SALT, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    a = ADJ[int.from_bytes(d[0:2], "big") % len(ADJ)]
    b = NOUN[int.from_bytes(d[2:4], "big") % len(NOUN)]
    return f"{a}{b}-{d[4:6].hex().upper()}"


def fingerprint(pk: bytes) -> str:
    h = hashlib.blake2b(pk, digest_size=8).hexdigest().upper()
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


NICK_RE = re.compile(r"[A-Z][A-Za-z]{2,24}[A-Z][A-Za-z]{1,24}-[0-9A-F]{4}")


def valid_nick(nick) -> bool:
    """fullmatch: '$' aceitaria uma quebra de linha no fim, e o nick pareceria o de outra pessoa."""
    return isinstance(nick, str) and NICK_RE.fullmatch(nick) is not None


# ================================================================ identidade local
def config_dir() -> Path:
    if os.environ.get("ARASAKA_HOLO_HOME"):
        return Path(os.environ["ARASAKA_HOLO_HOME"])
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / APP_ID
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_ID


class Identity:
    def __init__(self, nick: str, sk: SigningKey, source: str):
        self.nick = nick
        self.sk = sk
        self.source = source

    @property
    def vk(self) -> VerifyKey:
        return self.sk.verify_key

    @property
    def pk_b64(self) -> str:
        return base64.b64encode(bytes(self.vk)).decode()

    @property
    def fp(self) -> str:
        return fingerprint(bytes(self.vk))

    # export / import (backup da chave para manter o nick depois de reinstalar)
    def export(self, password: str | None = None) -> str:
        """Backup da chave. Com senha (formato 2): Argon2id + XSalsa20-Poly1305; sem senha (formato 1): texto puro."""
        plain = {"holo": 1, "nick": self.nick, "sk": base64.b64encode(bytes(self.sk)).decode()}
        if not password:
            return json.dumps(plain)
        salt = os.urandom(pwhash.argon2id.SALTBYTES)
        key = pwhash.argon2id.kdf(SecretBox.KEY_SIZE, password.encode("utf-8"), salt,
                                  opslimit=pwhash.argon2id.OPSLIMIT_MODERATE, memlimit=pwhash.argon2id.MEMLIMIT_MODERATE)
        box = SecretBox(key).encrypt(json.dumps(plain).encode("utf-8"))
        return json.dumps({"holo": 2, "nick": self.nick, "kdf": "argon2id-moderate",
                           "salt": base64.b64encode(salt).decode(), "box": base64.b64encode(bytes(box)).decode()})

    @staticmethod
    def key_path() -> Path:
        return config_dir() / "identity.key"


def _write_private(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    # ja nasce com 0600 (no Windows, quem protege e a permissao da pasta do usuario)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def _keep_aside(path: Path, tag: str):
    """Guarda o arquivo da chave com outro nome: uma chave nunca e sobrescrita."""
    if path.exists():
        base = f"identity-{tag}-{time.strftime('%Y%m%d-%H%M%S')}"
        dest, n = path.with_name(base + ".key"), 1
        while dest.exists():
            dest, n = path.with_name(f"{base}-{n}.key"), n + 1
        path.replace(dest)


def _read_state(path: Path) -> dict | None:
    """None = ainda nao existe. {} = existe, mas esta corrompido. Erro de leitura (permissao, disco) sobe."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except UnicodeDecodeError:
        return {}
    try:
        d = json.loads(raw)
        if len(base64.b64decode(d["sk"], validate=True)) == 32 and valid_nick(d["nick"]):
            return d
    except (ValueError, KeyError, TypeError):
        pass
    return {}


def _store(nick: str, sk: SigningKey):
    _write_private(Identity.key_path(), json.dumps({"holo": 1, "nick": nick,
                                                    "sk": base64.b64encode(bytes(sk)).decode()}))


def load_identity() -> Identity:
    """Carrega (ou cria, so na primeira vez) a identidade deste computador."""
    path = Identity.key_path()
    state = _read_state(path)
    if state:
        return Identity(state["nick"], SigningKey(base64.b64decode(state["sk"])), "salvo neste computador")
    if state == {}:
        _keep_aside(path, "corrompida")
    mac, source = pick_mac()
    if mac:
        nick = nick_from_mac(mac)
    else:
        # sem MAC utilizavel: nick aleatorio, salvo para sempre neste perfil
        nick = nick_from_mac(os.urandom(6).hex())
        source = "aleatorio (sem placa de rede fisica)"
    sk = SigningKey.generate()
    _store(nick, sk)
    return Identity(nick, sk, source)


def backup_needs_password(text: str) -> bool:
    try:
        return json.loads(text).get("holo") == 2
    except Exception:
        return False


def import_identity(text: str, password: str | None = None) -> Identity:
    d = json.loads(text)
    if d.get("holo") == 2:
        if not password:
            raise ValueError("esse backup tem senha")
        key = pwhash.argon2id.kdf(SecretBox.KEY_SIZE, password.encode("utf-8"), base64.b64decode(d["salt"]),
                                  opslimit=pwhash.argon2id.OPSLIMIT_MODERATE, memlimit=pwhash.argon2id.MEMLIMIT_MODERATE)
        try:
            d = json.loads(SecretBox(key).decrypt(base64.b64decode(d["box"])).decode("utf-8"))
        except CryptoError:
            raise ValueError("senha errada") from None
    if d.get("holo") != 1 or not valid_nick(d.get("nick")):
        raise ValueError("arquivo de identidade invalido")
    try:
        sk = SigningKey(base64.b64decode(d["sk"], validate=True))
    except Exception:
        raise ValueError("arquivo de identidade invalido") from None
    path = Identity.key_path()
    old = _read_state(path)
    if old is not None and old.get("sk") != d["sk"]:
        _keep_aside(path, old.get("nick") or "corrompida")
    _store(d["nick"], sk)
    return Identity(d["nick"], sk, "importado")
