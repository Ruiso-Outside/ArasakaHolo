"""
ARASAKA HOLO // criptografia (libsodium via PyNaCl).

Salas:   chave = Argon2id(senha da sala, sal = BLAKE2b(nome da sala))
         id enviado ao servidor = BLAKE2b(chave)  -> o servidor nao recebe o nome nem a senha
         mensagem = XSalsa20-Poly1305( Ed25519-assinado({nick, chave publica, contexto, texto, hora, ttl, id}) )
Diretas: Curve25519 (convertida da chave Ed25519 de cada um) + XSalsa20-Poly1305 (crypto_box),
         com o conteudo tambem assinado. Somente o destinatario abre.
O servidor so ve blobs cifrados, ids de sala e o nick do destinatario de mensagens diretas.

O 'contexto' assinado (v2) diz em que sala, ou entre quais duas chaves, a mensagem vale: ninguem consegue pegar
uma mensagem direta sua e publicar numa sala (ou levar de uma sala para outra) como se fosse sua.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from urllib.parse import urlsplit

from nacl import pwhash
from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

from .identity import valid_nick

PROTO = 1              # protocolo de transporte (cliente <-> relay)
AUTH = 2               # autenticacao: 2 = assinatura presa ao endereco do servidor
MSG_V = 2              # formato das mensagens: 2 = com contexto assinado
POW_BITS = 18          # prova de trabalho exigida para registrar um nick novo (~1 s)
MAX_TEXT = 4000
MAX_SKEW = 600         # s: mensagem com hora mais distante que isso aparece marcada (possivel repeticao)


class OldMessage(Exception):
    """Mensagem de uma versao antiga do HOLO (sem contexto assinado): nao e aceita."""

    def __init__(self, nick: str = ""):
        super().__init__(nick)
        self.nick = nick


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def ub64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


# ================================================================ salas
def room_key(name: str, password: str) -> bytes:
    """Chave simetrica da sala. Sem senha: a propria sala e a senha (sala 'publica')."""
    name = name.strip().lower()
    secret = (password or name).encode("utf-8")
    salt = hashlib.blake2b(name.encode("utf-8"), digest_size=pwhash.argon2id.SALTBYTES,
                           person=b"holo-room-salt").digest()
    return pwhash.argon2id.kdf(SecretBox.KEY_SIZE, secret, salt,
                               opslimit=pwhash.argon2id.OPSLIMIT_INTERACTIVE,
                               memlimit=pwhash.argon2id.MEMLIMIT_INTERACTIVE)


def room_id(key: bytes) -> str:
    return hashlib.blake2b(key, digest_size=20, person=b"holo-room-id").hexdigest()


def room_ctx(key: bytes) -> str:
    return "room|" + room_id(key)


def dm_ctx(from_pk: str, to_pk: str) -> str:
    return f"dm|{from_pk}|{to_pk}"


def _signed_payload(sk: SigningKey, nick: str, ctx: str, text: str, ttl: int, data: dict | None) -> bytes:
    body = {"v": MSG_V, "n": nick, "k": b64(bytes(sk.verify_key)), "c": ctx, "t": text[:MAX_TEXT],
            "ts": int(time.time()), "ttl": int(ttl), "id": os.urandom(8).hex()}
    if data is not None:
        body["d"] = data            # sinalizacao de call (nunca aparece como texto)
    return sk.sign(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _verify_payload(signed: bytes, ctx: str) -> dict | None:
    """Abre a assinatura com a chave publica que vem dentro da mensagem e confere o contexto e os campos.
    (Quem chama ainda confere se essa chave e a registrada para o nick.)"""
    body = json.loads(signed[64:].decode("utf-8"))     # 'signed message' do Ed25519 = assinatura(64) + mensagem
    VerifyKey(ub64(body["k"])).verify(signed)
    if not valid_nick(body.get("n")):
        return None
    if body.get("v") == 1:
        raise OldMessage(body["n"])
    if body.get("v") != MSG_V or body.get("c") != ctx:
        return None
    ok = (isinstance(body.get("t"), str) and len(body["t"]) <= MAX_TEXT
          and type(body.get("ts")) is int and 0 <= body["ts"] < 2 ** 33
          and type(body.get("ttl")) is int and 0 <= body["ttl"] <= 86400
          and isinstance(body.get("id"), str) and 8 <= len(body["id"]) <= 64
          and isinstance(body.get("d", {}), dict))
    return body if ok else None


_BAD = (CryptoError, ValueError, KeyError, TypeError, AttributeError)   # BadSignatureError e um CryptoError


def seal_room(key: bytes, sk: SigningKey, nick: str, text: str, ttl: int = 0, data: dict | None = None) -> str:
    return b64(SecretBox(key).encrypt(_signed_payload(sk, nick, room_ctx(key), text, ttl, data)))


def open_room(key: bytes, blob: str) -> dict | None:
    try:
        return _verify_payload(SecretBox(key).decrypt(ub64(blob)), room_ctx(key))
    except _BAD:
        return None


# ================================================================ mensagens diretas
def box_keys(sk: SigningKey) -> PrivateKey:
    return sk.to_curve25519_private_key()


def box_pub(vk_b64: str) -> PublicKey:
    return VerifyKey(ub64(vk_b64)).to_curve25519_public_key()


def valid_pk(vk_b64) -> bool:
    try:
        box_pub(vk_b64)
        return True
    except (*_BAD, RuntimeError):
        return False


def seal_dm(sk: SigningKey, nick: str, peer_vk_b64: str, text: str, ttl: int = 0, data: dict | None = None) -> str:
    ctx = dm_ctx(b64(bytes(sk.verify_key)), peer_vk_b64)
    return b64(Box(box_keys(sk), box_pub(peer_vk_b64)).encrypt(_signed_payload(sk, nick, ctx, text, ttl, data)))


def open_dm(sk: SigningKey, sender_vk_b64: str, blob: str) -> dict | None:
    try:
        box = Box(box_keys(sk), box_pub(sender_vk_b64))
        body = _verify_payload(box.decrypt(ub64(blob)), dm_ctx(sender_vk_b64, b64(bytes(sk.verify_key))))
        return body if body and body["k"] == sender_vk_b64 else None
    except (*_BAD, RuntimeError):
        return None


class Replay:
    """Lembra os ids ja vistos: a mesma mensagem repetida (pelo servidor ou por alguem da sala) e ignorada."""

    def __init__(self, limit: int = 20000):
        self.limit = limit
        self.seen: dict[tuple[str, str], None] = {}

    def fresh(self, body: dict) -> bool:
        k = (body["k"], body["id"])
        if k in self.seen:
            return False
        self.seen[k] = None
        if len(self.seen) > self.limit:
            del self.seen[next(iter(self.seen))]
        return True

    @staticmethod
    def on_time(body: dict, skew: int = MAX_SKEW) -> bool:
        return abs(time.time() - body["ts"]) <= skew


# ================================================================ autenticacao no servidor
def host_id(netloc: str) -> str:
    """'Piphin.Online:443' -> 'piphin.online'. As portas padrao (80 e 443) somem, as outras ficam."""
    try:
        p = urlsplit("//" + netloc.strip())
        host, port = (p.hostname or ""), p.port
        if not host.isascii():
            host = host.encode("idna").decode()
    except ValueError:
        return ""
    return f"{host}:{port}" if port and port not in (80, 443) else host


def url_host(url: str) -> str:
    return host_id(urlsplit(url).netloc.rpartition("@")[2])


def pow_ok(challenge: str, nick: str, pk_b64: str, nonce: int, bits: int = POW_BITS) -> bool:
    h = hashlib.sha256(f"{challenge}|{nick}|{pk_b64}|{nonce}".encode()).digest()
    v = int.from_bytes(h, "big")
    return v >> (256 - bits) == 0


def solve_pow(challenge: str, nick: str, pk_b64: str, bits: int = POW_BITS) -> int:
    n = 0
    while not pow_ok(challenge, nick, pk_b64, n, bits):
        n += 1
    return n


def _auth_text(challenge: str, nick: str, host: str) -> bytes:
    # o endereco entra na assinatura: um servidor mal-intencionado nao consegue reaproveitar a sua assinatura
    # para entrar com o seu nick em outro servidor
    return f"HOLO-AUTH2|{host}|{challenge}|{nick}".encode()


def auth_signature(sk: SigningKey, challenge: str, nick: str, host: str) -> str:
    return b64(sk.sign(_auth_text(challenge, nick, host)).signature)


def check_auth(pk_b64: str, challenge: str, nick: str, sig_b64: str, host: str, legacy: bool = True) -> bool:
    """legacy: aceita tambem a assinatura antiga (HOLO 1.1 e anteriores), sem o endereco."""
    try:
        vk, sig = VerifyKey(ub64(pk_b64)), ub64(sig_b64)
    except _BAD:
        return False
    for t in [_auth_text(challenge, nick, host)] + ([f"HOLO-AUTH|{challenge}|{nick}".encode()] if legacy else []):
        try:
            vk.verify(t, sig)
            return True
        except _BAD:
            continue
    return False
