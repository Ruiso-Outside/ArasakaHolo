"""
ARASAKA HOLO // criptografia (libsodium via PyNaCl).

Salas:   chave = Argon2id(senha da sala, sal = BLAKE2b(nome da sala))
         id enviado ao servidor = BLAKE2b(chave)  -> o servidor nao sabe o nome nem a senha
         mensagem = XSalsa20-Poly1305( Ed25519-assinado({nick, chave publica, texto, hora, ttl}) )
Diretas: Curve25519 (convertida da chave Ed25519 de cada um) + XSalsa20-Poly1305 (crypto_box),
         com o conteudo tambem assinado. Somente o destinatario abre.
O servidor so ve blobs cifrados, ids de sala e o nick do destinatario de mensagens diretas.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time

from nacl import pwhash
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

PROTO = 1
POW_BITS = 18          # prova de trabalho exigida para registrar um nick novo (~1 s)
MAX_TEXT = 4000


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def ub64(s: str) -> bytes:
    return base64.b64decode(s)


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


def _signed_payload(sk: SigningKey, nick: str, text: str, ttl: int, extra: dict | None = None) -> bytes:
    body = {"v": PROTO, "n": nick, "k": b64(bytes(sk.verify_key)), "t": text[:MAX_TEXT],
            "ts": int(time.time()), "ttl": int(ttl), "id": os.urandom(8).hex()}
    if extra:
        body.update(extra)
    return sk.sign(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _verify_payload(signed: bytes) -> dict:
    """Abre a assinatura usando a chave publica que vem dentro da mensagem.
    (Quem chama ainda confere se essa chave e a registrada para o nick.)"""
    # formato Ed25519 'signed message' = assinatura(64) + mensagem
    msg = signed[64:]
    body = json.loads(msg.decode("utf-8"))
    VerifyKey(ub64(body["k"])).verify(signed)
    return body


def seal_room(key: bytes, sk: SigningKey, nick: str, text: str, ttl: int = 0) -> str:
    return b64(SecretBox(key).encrypt(_signed_payload(sk, nick, text, ttl)))


def open_room(key: bytes, blob: str) -> dict | None:
    try:
        return _verify_payload(SecretBox(key).decrypt(ub64(blob)))
    except (CryptoError, BadSignatureError, ValueError, KeyError, json.JSONDecodeError):
        return None


# ================================================================ mensagens diretas
def box_keys(sk: SigningKey) -> PrivateKey:
    return sk.to_curve25519_private_key()


def box_pub(vk_b64: str) -> PublicKey:
    return VerifyKey(ub64(vk_b64)).to_curve25519_public_key()


def seal_dm(sk: SigningKey, nick: str, peer_vk_b64: str, text: str, ttl: int = 0, to: str = "") -> str:
    box = Box(box_keys(sk), box_pub(peer_vk_b64))
    return b64(box.encrypt(_signed_payload(sk, nick, text, ttl, {"to": to})))


def open_dm(sk: SigningKey, sender_vk_b64: str, blob: str) -> dict | None:
    try:
        box = Box(box_keys(sk), box_pub(sender_vk_b64))
        body = _verify_payload(box.decrypt(ub64(blob)))
        return body if body.get("k") == sender_vk_b64 else None
    except (CryptoError, BadSignatureError, ValueError, KeyError, json.JSONDecodeError):
        return None


# ================================================================ autenticacao no servidor
def pow_ok(challenge: str, nick: str, pk_b64: str, nonce: int, bits: int = POW_BITS) -> bool:
    h = hashlib.sha256(f"{challenge}|{nick}|{pk_b64}|{nonce}".encode()).digest()
    v = int.from_bytes(h, "big")
    return v >> (256 - bits) == 0


def solve_pow(challenge: str, nick: str, pk_b64: str, bits: int = POW_BITS) -> int:
    n = 0
    while not pow_ok(challenge, nick, pk_b64, n, bits):
        n += 1
    return n


def auth_signature(sk: SigningKey, challenge: str, nick: str) -> str:
    return b64(sk.sign(f"HOLO-AUTH|{challenge}|{nick}".encode()).signature)


def check_auth(pk_b64: str, challenge: str, nick: str, sig_b64: str) -> bool:
    try:
        VerifyKey(ub64(pk_b64)).verify(f"HOLO-AUTH|{challenge}|{nick}".encode(), ub64(sig_b64))
        return True
    except (BadSignatureError, ValueError):
        return False
