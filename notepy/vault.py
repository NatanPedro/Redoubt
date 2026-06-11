"""Cofre cifrado do Redoubt — guarda segredo de PROPOSITO (zero-knowledge).

Diferente da Sentinela (que *detecta* padrao), o Cofre nao adivinha nada: voce
DECLARA que o conteudo e segredo e ele e cifrado em repouso.

Cripto (formato RDBT2 — "envelope" / key-slots, estilo LUKS/age):
  - Uma CHAVE-DE-CONTEUDO (CK) aleatoria de 256 bits cifra o texto (AES-256-GCM).
  - Cada DESTRAVADOR (senha OU arquivo-chave) e um SLOT que "embrulha" a CK com uma
    chave derivada (scrypt). Varias senhas/keyfiles independentes abrem o MESMO cofre;
    re-cifrar = trocar os slots (sem re-derivar tudo).
  - Zero-knowledge: nenhuma senha/keyfile e gravada. Sem backdoor nem recuperacao.

Formato RDBT2 (binario):
  [0:5]   MAGIC b"RDBT2"
  [5]     versao (1)
  [6]     nslots (1..16)
  depois nslots SLOTS de 80 bytes cada:
    [0]     kind (0=senha, 1=arquivo-chave)
    [1:4]   log2n, r, p (scrypt)
    [4:20]  salt (16)
    [20:32] wrap_nonce (12)
    [32:80] CK embrulhada (48 = 32 + tag GCM)  — AAD = os 32 bytes do cabecalho do slot
  depois:
    content_nonce (12)
    content_ct (resto)  — AES-256-GCM(CK); AAD = todo o cabecalho + slots (anti-strip)

Le tambem o formato legado RDBT1 (senha unica) e o migra em memoria para RDBT2.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC_V1 = b"RDBT1"
MAGIC_V2 = b"RDBT2"
VERSION = 1
_KEY_LEN = 32          # AES-256 / tamanho da CK
_SALT_LEN = 16
_NONCE_LEN = 12
_HEADER_V1_LEN = 37    # 5 + 1 + 1 + 1 + 1 + 16 + 12
_SLOT_LEN = 80         # 1 + 3 + 16 + 12 + 48
_WRAPPED_LEN = 48      # CK (32) + tag GCM (16)
_MAX_SLOTS = 16

KIND_PASSWORD = 0
KIND_KEYFILE = 1

_DEFAULT_LOG2N = 15    # n = 2**15 (~32 MB), bom para uso interativo
_DEFAULT_R = 8
_DEFAULT_P = 1


class VaultError(Exception):
    """Erro generico do cofre."""


class NotAVault(VaultError):
    """Os bytes nao sao um cofre .rdbt valido (MAGIC ausente)."""


class WrongPassword(VaultError):
    """Credencial incorreta OU conteudo adulterado (verificacao GCM falhou)."""


@dataclass
class Opened:
    """Resultado de abrir um cofre: texto + a chave-de-conteudo e os slots crus,
    para re-selar PRESERVANDO todos os destravadores."""
    text: str
    key: bytes
    slots: list[bytes]


# --------------------------------------------------------------------------- #
# KDF / material
# --------------------------------------------------------------------------- #
def _scrypt(material: bytes, salt: bytes, log2n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=_KEY_LEN, n=2 ** log2n, r=r, p=p).derive(material)


def _check_kdf(log2n: int, r: int, p: int) -> None:
    # Defesa contra .rdbt malicioso: log2n grande (ex.: 63) faria o scrypt alocar
    # petabytes e derrubar o app. Limita os parametros.
    if not (1 <= log2n <= 18 and 1 <= r <= 16 and 1 <= p <= 16):
        raise VaultError(f"parametros de KDF fora dos limites (n=2^{log2n}, r={r}, p={p})")


def _material(kind: int, secret) -> bytes:
    """Material que entra no scrypt: senha em utf-8; arquivo-chave -> sha256 (pode ser grande)."""
    if kind == KIND_PASSWORD:
        return secret.encode("utf-8", "surrogatepass") if isinstance(secret, str) else bytes(secret)
    return hashlib.sha256(bytes(secret)).digest()


# --------------------------------------------------------------------------- #
# Slots
# --------------------------------------------------------------------------- #
def _make_slot(ck: bytes, kind: int, secret, log2n: int, r: int, p: int) -> bytes:
    salt = os.urandom(_SALT_LEN)
    wrap_nonce = os.urandom(_NONCE_LEN)
    head = bytes([kind, log2n, r, p]) + salt + wrap_nonce        # 32 bytes (AAD do slot)
    kek = _scrypt(_material(kind, secret), salt, log2n, r, p)
    wrapped = AESGCM(kek).encrypt(wrap_nonce, ck, head)          # 48 bytes
    return head + wrapped


def make_password_slot(ck: bytes, password: str,
                       log2n: int = _DEFAULT_LOG2N, r: int = _DEFAULT_R, p: int = _DEFAULT_P) -> bytes:
    if not password:
        raise VaultError("senha-mestra vazia")
    return _make_slot(ck, KIND_PASSWORD, password, log2n, r, p)


def make_keyfile_slot(ck: bytes, keyfile: bytes,
                      log2n: int = _DEFAULT_LOG2N, r: int = _DEFAULT_R, p: int = _DEFAULT_P) -> bytes:
    if not keyfile:
        raise VaultError("arquivo-chave vazio")
    return _make_slot(ck, KIND_KEYFILE, keyfile, log2n, r, p)


def add_unlocker(ck: bytes, slots: list[bytes], *, password: str | None = None,
                 keyfile: bytes | None = None) -> list[bytes]:
    """Devolve a lista de slots com um novo destravador (senha ou arquivo-chave)."""
    new = list(slots)
    if password:
        new.append(make_password_slot(ck, password))
    if keyfile:
        new.append(make_keyfile_slot(ck, keyfile))
    if len(new) > _MAX_SLOTS:
        raise VaultError(f"maximo de {_MAX_SLOTS} destravadores por cofre")
    return new


def generate_key() -> bytes:
    return os.urandom(_KEY_LEN)


# --------------------------------------------------------------------------- #
# Montagem / leitura
# --------------------------------------------------------------------------- #
def _assemble(ck: bytes, slots: list[bytes], plaintext: str) -> bytes:
    if not slots:
        raise VaultError("cofre sem destravadores")
    if len(slots) > _MAX_SLOTS:
        raise VaultError(f"maximo de {_MAX_SLOTS} destravadores por cofre")
    header = bytes([*MAGIC_V2, VERSION, len(slots)])
    body = b"".join(slots)
    aad = header + body                                          # anti-strip de slots
    content_nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(ck).encrypt(content_nonce, plaintext.encode("utf-8", "surrogatepass"), aad)
    return header + body + content_nonce + ct


def new_vault(plaintext: str, *, password: str | None = None,
              keyfile: bytes | None = None) -> bytes:
    """Cria um cofre RDBT2 novo com os destravadores dados (>=1)."""
    ck = generate_key()
    slots = add_unlocker(ck, [], password=password, keyfile=keyfile)
    return _assemble(ck, slots, plaintext)


def reseal(plaintext: str, key: bytes, slots: list[bytes]) -> bytes:
    """Re-cifra o conteudo sob a MESMA CK e slots (preserva todos os destravadores)."""
    return _assemble(key, slots, plaintext)


def open_vault(blob: bytes, *, password: str | None = None,
               keyfile: bytes | None = None) -> Opened:
    """Abre um cofre (RDBT2 ou RDBT1 legado). Levanta NotAVault/WrongPassword/VaultError."""
    if blob[:5] == MAGIC_V1:
        text = _decrypt_v1(blob, password or "")
        ck = generate_key()                                     # migra em memoria p/ RDBT2
        return Opened(text, ck, [make_password_slot(ck, password or "")])
    if blob[:5] != MAGIC_V2:
        raise NotAVault("nao e um cofre .rdbt (MAGIC ausente)")
    if len(blob) < 7:
        raise VaultError("cofre truncado")
    if blob[5] != VERSION:
        raise VaultError(f"versao de cofre nao suportada: {blob[5]}")
    nslots = blob[6]
    if not (1 <= nslots <= _MAX_SLOTS):
        raise VaultError(f"numero de slots invalido: {nslots}")
    end_slots = 7 + _SLOT_LEN * nslots
    if len(blob) < end_slots + _NONCE_LEN:
        raise VaultError("cofre truncado")
    slots = [blob[7 + i * _SLOT_LEN: 7 + (i + 1) * _SLOT_LEN] for i in range(nslots)]
    content_nonce = blob[end_slots:end_slots + _NONCE_LEN]
    ct = blob[end_slots + _NONCE_LEN:]
    aad = blob[:end_slots]

    ck = None
    for slot in slots:
        kind, log2n, r, p = slot[0], slot[1], slot[2], slot[3]
        if kind == KIND_PASSWORD and password is not None:
            secret = password
        elif kind == KIND_KEYFILE and keyfile is not None:
            secret = keyfile
        else:
            continue
        _check_kdf(log2n, r, p)
        salt, wrap_nonce, wrapped = slot[4:20], slot[20:32], slot[32:80]
        kek = _scrypt(_material(kind, secret), salt, log2n, r, p)
        try:
            ck = AESGCM(kek).decrypt(wrap_nonce, wrapped, slot[:32])
            break
        except InvalidTag:
            ck = None
    if ck is None:
        raise WrongPassword("credencial incorreta ou cofre adulterado")
    try:
        pt = AESGCM(ck).decrypt(content_nonce, ct, aad)
    except InvalidTag:
        raise WrongPassword("conteudo adulterado") from None
    return Opened(pt.decode("utf-8", "surrogatepass"), ck, slots)


def slot_kinds(blob: bytes) -> list[int]:
    """Tipos de slot do cofre (0=senha, 1=keyfile). RDBT1 -> [0]. Util p/ a UI."""
    if blob[:5] == MAGIC_V1:
        return [KIND_PASSWORD]
    if blob[:5] != MAGIC_V2 or len(blob) < 7:
        return []
    nslots = blob[6]
    if not (1 <= nslots <= _MAX_SLOTS) or len(blob) < 7 + _SLOT_LEN * nslots:
        return []
    return [blob[7 + i * _SLOT_LEN] for i in range(nslots)]


# --------------------------------------------------------------------------- #
# Compatibilidade / API simples
# --------------------------------------------------------------------------- #
def encrypt(plaintext: str, password: str) -> bytes:
    """Cria um cofre RDBT2 com uma unica senha (API compativel)."""
    return new_vault(plaintext, password=password)


def decrypt(blob: bytes, password: str | None = None, *, keyfile: bytes | None = None) -> str:
    """Abre um cofre e devolve so o texto (API compativel)."""
    return open_vault(blob, password=password, keyfile=keyfile).text


def looks_like_vault(blob: bytes) -> bool:
    """True se os bytes comecam com um MAGIC de cofre (RDBT1 ou RDBT2)."""
    return blob[:5] in (MAGIC_V1, MAGIC_V2)


def is_vault_file(path: str) -> bool:
    """True se o arquivo em `path` e um cofre (checa o MAGIC, nao a extensao)."""
    try:
        with open(path, "rb") as fh:
            return looks_like_vault(fh.read(5))
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Legado RDBT1 (senha unica) — leitura para migrar
# --------------------------------------------------------------------------- #
def _decrypt_v1(blob: bytes, password: str) -> str:
    if len(blob) < _HEADER_V1_LEN:
        raise VaultError("cofre RDBT1 truncado")
    if blob[5] != VERSION:
        raise VaultError(f"versao de cofre nao suportada: {blob[5]}")
    log2n, r, p = blob[6], blob[7], blob[8]
    _check_kdf(log2n, r, p)
    salt, nonce = blob[9:25], blob[25:37]
    key = _scrypt(password.encode("utf-8", "surrogatepass"), salt, log2n, r, p)
    try:
        pt = AESGCM(key).decrypt(nonce, blob[_HEADER_V1_LEN:], blob[:_HEADER_V1_LEN])
    except InvalidTag:
        raise WrongPassword("senha incorreta ou conteudo adulterado") from None
    return pt.decode("utf-8", "surrogatepass")
