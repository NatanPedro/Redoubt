"""Cofre cifrado do Redoubt — guarda segredo de PROPOSITO (zero-knowledge).

Diferente da Sentinela (que *detecta* padrao), o Cofre nao adivinha nada: voce
DECLARA que o conteudo e segredo e ele e cifrado em repouso.

Cripto (formato RDBT4 — "envelope" / key-slots, estilo LUKS/age):
  - Uma CHAVE-DE-CONTEUDO (CK) aleatoria de 256 bits cifra o texto (AES-256-GCM).
  - Cada DESTRAVADOR e um SLOT que "embrulha" a CK. Tres tipos:
      senha / arquivo-chave  -> KEK derivada por KDF (Argon2id; le scrypt legado).
      destinatario X25519     -> KEK por ECDH efemero (cifrar-PARA a chave publica de alguem).
    Varios slots independentes abrem o MESMO cofre; re-cifrar = trocar os slots.
  - Zero-knowledge: nenhuma senha/keyfile e gravada. Sem backdoor nem recuperacao.

Slots de TAMANHO VARIAVEL (length-prefixed) — necessario porque o slot X25519 carrega uma
chave efemera de 32 bytes que nao cabe no slot fixo de 80 bytes do RDBT3. Cada slot:
    [0]      kind: nibble baixo = 0(senha)/1(arquivo-chave)/2(X25519); nibble alto = KDF (senha/keyfile)
    [1:3]    len do payload (big-endian, 2 bytes)
    [3:...]  payload:
               senha/keyfile: params(3) + salt(16) + wrap_nonce(12) + CK_embrulhada(48)  = 79
               X25519:        eph_pubkey(32)            + CK_embrulhada(48)               = 80  (nonce derivado por HKDF)
A AAD do embrulho do slot = `kind` + metadata (TUDO menos a CK embrulhada), SEM o prefixo de
tamanho — entao bate byte-a-byte com a AAD do RDBT3, e um slot fixo-80 legado e re-enquadrado
para RDBT4 sem reembrulhar (o prefixo de tamanho e autenticado pela AAD do CONTEUDO, anti-strip).

Formato RDBT4 (binario):
  [0:5]  MAGIC b"RDBT4"   (le tambem RDBT3/RDBT2 fixo-80, convertendo, e RDBT1 legado)
  [5]    versao (1)
  [6]    nslots (1..16)
  depois nslots SLOTS (variaveis, como acima)
  depois:
    content_nonce(12) + content_ct  — AES-256-GCM(CK); AAD = todo o cabecalho + slots (anti-strip)
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC_V1 = b"RDBT1"
MAGIC_V2 = b"RDBT2"
MAGIC_V3 = b"RDBT3"
MAGIC_V4 = b"RDBT4"
VERSION = 1
_KEY_LEN = 32          # AES-256 / tamanho da CK
_SALT_LEN = 16
_NONCE_LEN = 12
_HEADER_V1_LEN = 37    # 5 + 1 + 1 + 1 + 1 + 16 + 12
_SLOT80_LEN = 80       # slot fixo legado (RDBT2/RDBT3): 1 + 3 + 16 + 12 + 48
_WRAPPED_LEN = 48      # CK (32) + tag GCM (16)
_LEN_BYTES = 2
_MAX_SLOT_PAYLOAD = 1024   # teto de sanidade do payload de um slot (anti-blob malicioso)
_MAX_SLOTS = 16
_X25519_LEN = 32
_X25519_INFO = b"redoubt-x25519-v1"

# Nibble baixo do byte `kind`: tipo de destravador.
KIND_PASSWORD = 0
KIND_KEYFILE = 1
KIND_X25519 = 2
# Nibble alto do byte `kind` (senha/keyfile): qual KDF derivou a KEK.
KDF_SCRYPT = 0
KDF_ARGON2 = 1

# scrypt (legado: leitura de slots/cofres antigos e do RDBT1)
_DEFAULT_LOG2N = 15
_DEFAULT_R = 8
_DEFAULT_P = 1

# Argon2id (padrao novo). memory_cost = 2**MEMLOG2 KiB. Lidos do modulo em tempo de chamada
# (testes podem reduzir via monkeypatch).
_DEFAULT_ARGON_T = 3
_DEFAULT_ARGON_MEMLOG2 = 16
_DEFAULT_ARGON_LANES = 4

# Orcamento anti-DoS (custo de KDF por slot e agregado). Ver historico do red-team do Argon2id.
_MAX_KDF_MEM = 128 * 1024 * 1024
_MAX_KDF_WORK = 1 << 20
_MAX_TOTAL_KDF_WORK = 1 << 22


class VaultError(Exception):
    """Erro generico do cofre."""


class NotAVault(VaultError):
    """Os bytes nao sao um cofre .rdbt valido (MAGIC ausente)."""


class WrongPassword(VaultError):
    """Credencial incorreta OU conteudo adulterado (verificacao GCM falhou)."""


@dataclass
class Opened:
    """Resultado de abrir um cofre: texto + a chave-de-conteudo e os slots crus (ja no
    enquadramento RDBT4), para re-selar PRESERVANDO todos os destravadores."""
    text: str
    key: bytes
    slots: list[bytes]


# --------------------------------------------------------------------------- #
# KDF / material  (inalterado — toda a blindagem anti-DoS preservada)
# --------------------------------------------------------------------------- #
def _kdf_of(kind_byte: int) -> int:
    return (kind_byte >> 4) & 0x0F


def _base_kind(kind_byte: int) -> int:
    return kind_byte & 0x0F


def _scrypt(material: bytes, salt: bytes, log2n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=_KEY_LEN, n=2 ** log2n, r=r, p=p).derive(material)


def _argon2id(material: bytes, salt: bytes, t: int, memlog2: int, lanes: int) -> bytes:
    return Argon2id(salt=salt, length=_KEY_LEN, iterations=t, lanes=lanes,
                    memory_cost=1 << memlog2).derive(material)


def _scrypt_mem(log2n: int, r: int) -> int:
    return 128 * (1 << log2n) * r


def _argon_mem(memlog2: int) -> int:
    return (1 << memlog2) * 1024


def _scrypt_work(log2n: int, r: int, p: int) -> int:
    return (1 << log2n) * r * p


def _argon_work(memlog2: int, t: int) -> int:
    return (1 << memlog2) * t


def _check_scrypt(log2n: int, r: int, p: int) -> None:
    if not (1 <= log2n <= 18 and 1 <= r <= 16 and 1 <= p <= 4):
        raise VaultError(f"parametros scrypt fora dos limites (n=2^{log2n}, r={r}, p={p})")
    if _scrypt_mem(log2n, r) > _MAX_KDF_MEM or _scrypt_work(log2n, r, p) > _MAX_KDF_WORK:
        raise VaultError(f"custo scrypt excede o teto (~{_scrypt_mem(log2n, r) >> 20} MiB)")


def _check_argon(t: int, memlog2: int, lanes: int) -> None:
    if not (1 <= t <= 8 and 10 <= memlog2 <= 17 and 1 <= lanes <= 8):
        raise VaultError(f"parametros Argon2id fora dos limites (t={t}, mem=2^{memlog2} KiB, lanes={lanes})")
    if _argon_mem(memlog2) > _MAX_KDF_MEM or _argon_work(memlog2, t) > _MAX_KDF_WORK:
        raise VaultError(f"custo Argon2id excede o teto (~{_argon_mem(memlog2) >> 20} MiB)")


def _material(kind: int, secret) -> bytes:
    """Material que entra no KDF: senha em utf-8; arquivo-chave -> sha256 (pode ser grande)."""
    if kind == KIND_PASSWORD:
        return secret.encode("utf-8", "surrogatepass") if isinstance(secret, str) else bytes(secret)
    return hashlib.sha256(bytes(secret)).digest()


def _derive_kek(kind_byte: int, secret, p1: int, p2: int, p3: int, salt: bytes) -> bytes:
    """Deriva a KEK (senha/keyfile) pelo KDF do nibble alto. VaultError se KDF/parametros invalidos."""
    material = _material(_base_kind(kind_byte), secret)
    kdf = _kdf_of(kind_byte)
    if kdf == KDF_SCRYPT:
        _check_scrypt(p1, p2, p3)
        return _scrypt(material, salt, p1, p2, p3)
    if kdf == KDF_ARGON2:
        _check_argon(p1, p2, p3)
        return _argon2id(material, salt, p1, p2, p3)
    raise VaultError(f"KDF de slot desconhecido: {kdf}")


# --------------------------------------------------------------------------- #
# Slots RDBT4 (length-prefixed)
# --------------------------------------------------------------------------- #
def _slot_meta(slot: bytes) -> bytes:
    """Metadata do slot = payload SEM a CK embrulhada (params+salt+nonce, ou eph_pubkey)."""
    return slot[3:-_WRAPPED_LEN]


def _slot_wrapped(slot: bytes) -> bytes:
    return slot[-_WRAPPED_LEN:]


def _slot_wrap_aad(slot: bytes) -> bytes:
    """AAD do embrulho = kind + metadata (SEM o prefixo de tamanho — bate com a AAD do RDBT3)."""
    return bytes([slot[0]]) + _slot_meta(slot)


def _frame(kind_byte: int, payload: bytes) -> bytes:
    """Enquadra um slot RDBT4: kind(1) + len(2) + payload."""
    return bytes([kind_byte]) + len(payload).to_bytes(_LEN_BYTES, "big") + payload


def _convert_legacy_slot(slot80: bytes) -> bytes:
    """Re-enquadra um slot fixo-80 (RDBT2/RDBT3) para RDBT4. A AAD do embrulho (kind+metadata)
    fica IDENTICA, entao a CK embrulhada continua valida sem reembrulhar."""
    return _frame(slot80[0], slot80[1:])      # payload = params+salt+nonce+wrapped (79)


def _slot_kdf_work(slot: bytes) -> int:
    """Custo estimado do KDF do slot (0 se X25519/invalido — nao soma ao orcamento anti-DoS)."""
    kind_byte = slot[0]
    if _base_kind(kind_byte) == KIND_X25519:
        return 0
    meta = _slot_meta(slot)
    if len(meta) < 3:
        return 0
    a, b, c = meta[0], meta[1], meta[2]
    kdf = _kdf_of(kind_byte)
    try:
        if kdf == KDF_SCRYPT:
            _check_scrypt(a, b, c)
            return _scrypt_work(a, b, c)
        if kdf == KDF_ARGON2:
            _check_argon(a, b, c)
            return _argon_work(b, a)
    except VaultError:
        return 0
    return 0


def _make_slot(ck: bytes, base_kind: int, secret) -> bytes:
    """Slot senha/keyfile novo (Argon2id). Le os params padrao do modulo em tempo de chamada."""
    t, memlog2, lanes = _DEFAULT_ARGON_T, _DEFAULT_ARGON_MEMLOG2, _DEFAULT_ARGON_LANES
    salt = os.urandom(_SALT_LEN)
    wrap_nonce = os.urandom(_NONCE_LEN)
    kind_byte = base_kind | (KDF_ARGON2 << 4)
    meta = bytes([t, memlog2, lanes]) + salt + wrap_nonce          # 31
    kek = _argon2id(_material(base_kind, secret), salt, t, memlog2, lanes)
    aad = bytes([kind_byte]) + meta                                # 32 (= AAD do RDBT3)
    wrapped = AESGCM(kek).encrypt(wrap_nonce, ck, aad)             # 48
    return _frame(kind_byte, meta + wrapped)


def make_password_slot(ck: bytes, password: str) -> bytes:
    if not password:
        raise VaultError("senha-mestra vazia")
    return _make_slot(ck, KIND_PASSWORD, password)


def make_keyfile_slot(ck: bytes, keyfile: bytes) -> bytes:
    if not keyfile:
        raise VaultError("arquivo-chave vazio")
    return _make_slot(ck, KIND_KEYFILE, keyfile)


def make_x25519_slot(ck: bytes, recipient_pub: bytes) -> bytes:
    """Embrulha a CK PARA um destinatario (chave publica X25519 de 32 bytes), via ECDH efemero.
    Nonce do GCM derivado por HKDF (a chave efemera torna a KEK unica -> par (chave,nonce) unico)."""
    if len(recipient_pub) != _X25519_LEN:
        raise VaultError("chave publica X25519 invalida (esperado 32 bytes)")
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    okm = HKDF(algorithm=hashes.SHA256(), length=_KEY_LEN + _NONCE_LEN,
               salt=epk + recipient_pub, info=_X25519_INFO).derive(shared)
    kek, wrap_nonce = okm[:_KEY_LEN], okm[_KEY_LEN:]
    aad = bytes([KIND_X25519]) + epk                               # 33
    wrapped = AESGCM(kek).encrypt(wrap_nonce, ck, aad)
    return _frame(KIND_X25519, epk + wrapped)


def _open_x25519(slot: bytes, x25519_private: bytes) -> bytes:
    """Tenta abrir um slot X25519 com a chave privada do destinatario. Levanta InvalidTag se nao for."""
    epk = _slot_meta(slot)
    if len(epk) != _X25519_LEN:
        raise VaultError("slot X25519 malformado")
    try:
        priv = X25519PrivateKey.from_private_bytes(x25519_private)
        my_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        # ValueError aqui = eph_pub de ordem baixa (shared all-zero, rejeitado pela lib) ou bytes
        # invalidos — tratamos como "slot nao abre", nunca crash.
        shared = priv.exchange(X25519PublicKey.from_public_bytes(epk))
    except ValueError as exc:
        raise VaultError("ponto/chave X25519 invalido (ordem baixa ou bytes invalidos)") from exc
    okm = HKDF(algorithm=hashes.SHA256(), length=_KEY_LEN + _NONCE_LEN,
               salt=epk + my_pub, info=_X25519_INFO).derive(shared)
    kek, wrap_nonce = okm[:_KEY_LEN], okm[_KEY_LEN:]
    return AESGCM(kek).decrypt(wrap_nonce, _slot_wrapped(slot), _slot_wrap_aad(slot))


def add_unlocker(ck: bytes, slots: list[bytes], *, password: str | None = None,
                 keyfile: bytes | None = None) -> list[bytes]:
    """Devolve a lista de slots com um novo destravador (senha ou arquivo-chave), em Argon2id."""
    new = list(slots)
    if password:
        new.append(make_password_slot(ck, password))
    if keyfile:
        new.append(make_keyfile_slot(ck, keyfile))
    if len(new) > _MAX_SLOTS:
        raise VaultError(f"maximo de {_MAX_SLOTS} destravadores por cofre")
    return new


def add_recipient(ck: bytes, slots: list[bytes], recipient_pub: bytes) -> list[bytes]:
    """Devolve a lista de slots com um novo destinatario X25519 (cifrar-para a chave publica dele)."""
    new = list(slots)
    new.append(make_x25519_slot(ck, recipient_pub))
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
    header = bytes([*MAGIC_V4, VERSION, len(slots)])
    body = b"".join(slots)
    aad = header + body                                          # anti-strip de slots
    content_nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(ck).encrypt(content_nonce, plaintext.encode("utf-8", "surrogatepass"), aad)
    return header + body + content_nonce + ct


def new_vault(plaintext: str, *, password: str | None = None,
              keyfile: bytes | None = None, recipient: bytes | None = None) -> bytes:
    """Cria um cofre RDBT4 novo com os destravadores dados (>=1): senha, arquivo-chave e/ou
    destinatario X25519 (`recipient` = chave publica de 32 bytes)."""
    ck = generate_key()
    slots = add_unlocker(ck, [], password=password, keyfile=keyfile)
    if recipient:
        slots = add_recipient(ck, slots, recipient)
    return _assemble(ck, slots, plaintext)


def reseal(plaintext: str, key: bytes, slots: list[bytes]) -> bytes:
    """Re-cifra o conteudo sob a MESMA CK e slots (preserva todos os destravadores)."""
    return _assemble(key, slots, plaintext)


def _parse_slots(blob: bytes, nslots: int, magic: bytes) -> tuple[list[bytes], int]:
    """Extrai os slots (sempre devolvidos no enquadramento RDBT4) e a posicao onde comeca o
    content_nonce. Converte slots fixo-80 (RDBT2/RDBT3) para RDBT4. Levanta VaultError se truncado."""
    slots: list[bytes] = []
    if magic in (MAGIC_V2, MAGIC_V3):
        end = 7 + _SLOT80_LEN * nslots
        if len(blob) < end + _NONCE_LEN:
            raise VaultError("cofre truncado")
        for i in range(nslots):
            slots.append(_convert_legacy_slot(blob[7 + i * _SLOT80_LEN: 7 + (i + 1) * _SLOT80_LEN]))
        return slots, end
    # RDBT4: slots length-prefixed
    pos = 7
    for _ in range(nslots):
        if pos + 3 > len(blob):
            raise VaultError("cofre truncado")
        plen = int.from_bytes(blob[pos + 1:pos + 3], "big")
        if not (_WRAPPED_LEN < plen <= _MAX_SLOT_PAYLOAD):
            raise VaultError(f"tamanho de slot invalido: {plen}")
        end = pos + 3 + plen
        if end > len(blob):
            raise VaultError("cofre truncado")
        slots.append(blob[pos:end])
        pos = end
    if len(blob) < pos + _NONCE_LEN:
        raise VaultError("cofre truncado")
    return slots, pos


def open_vault(blob: bytes, *, password: str | None = None,
               keyfile: bytes | None = None, x25519_private: bytes | None = None) -> Opened:
    """Abre um cofre (RDBT4/RDBT3/RDBT2 ou RDBT1 legado). Levanta NotAVault/WrongPassword/VaultError.

    Cada slot e aberto pelo seu tipo: senha/keyfile (KDF do nibble alto) ou X25519 (ECDH com a
    chave privada do destinatario). Slots de tipos diferentes convivem no mesmo cofre."""
    if blob[:5] == MAGIC_V1:
        text = _decrypt_v1(blob, password or "")
        ck = generate_key()                                     # migra em memoria p/ RDBT4
        return Opened(text, ck, [make_password_slot(ck, password or "")])
    magic = blob[:5]
    if magic not in (MAGIC_V2, MAGIC_V3, MAGIC_V4):
        raise NotAVault("nao e um cofre .rdbt (MAGIC ausente)")
    if len(blob) < 7:
        raise VaultError("cofre truncado")
    if blob[5] != VERSION:
        raise VaultError(f"versao de cofre nao suportada: {blob[5]}")
    nslots = blob[6]
    if not (1 <= nslots <= _MAX_SLOTS):
        raise VaultError(f"numero de slots invalido: {nslots}")
    slots, content_start = _parse_slots(blob, nslots, magic)
    content_nonce = blob[content_start:content_start + _NONCE_LEN]
    ct = blob[content_start + _NONCE_LEN:]
    aad = blob[:content_start]

    def _matches(s: bytes) -> bool:
        kb = _base_kind(s[0])
        return ((kb == KIND_PASSWORD and password is not None)
                or (kb == KIND_KEYFILE and keyfile is not None)
                or (kb == KIND_X25519 and x25519_private is not None))

    # Anti-DoS: recusa ANTES de derivar se o custo agregado de KDF dos slots que casam exceder o teto.
    if sum(_slot_kdf_work(s) for s in slots if _matches(s)) > _MAX_TOTAL_KDF_WORK:
        raise VaultError("custo de KDF agregado excede o orcamento (possivel cofre malicioso)")

    # Derivacao EM SERIE (pico de memoria = uma derivacao). Slot que nao abre e PULADO (nao fatal).
    ck = None
    for slot in slots:
        if not _matches(slot):
            continue
        try:
            if _base_kind(slot[0]) == KIND_X25519:
                ck = _open_x25519(slot, x25519_private)
            else:
                meta = _slot_meta(slot)
                if len(meta) < 3 + _SALT_LEN + _NONCE_LEN:    # params+salt+nonce: slot curto demais
                    continue                                   # pula (nao indexa meta curto -> sem crash)
                secret = password if _base_kind(slot[0]) == KIND_PASSWORD else keyfile
                kek = _derive_kek(slot[0], secret, meta[0], meta[1], meta[2], meta[3:19])
                ck = AESGCM(kek).decrypt(meta[19:31], _slot_wrapped(slot), _slot_wrap_aad(slot))
            break
        except (VaultError, InvalidTag, ValueError, IndexError):
            # QUALQUER slot malformado (params/nonce/ponto X25519 invalido) e PULADO, nunca fatal.
            ck = None
            continue
    if ck is None:
        raise WrongPassword("credencial incorreta ou cofre adulterado")
    try:
        pt = AESGCM(ck).decrypt(content_nonce, ct, aad)
    except InvalidTag:
        raise WrongPassword("conteudo adulterado") from None
    return Opened(pt.decode("utf-8", "surrogatepass"), ck, slots)


def slot_kinds(blob: bytes) -> list[int]:
    """Tipos de slot (0=senha, 1=keyfile, 2=X25519). RDBT1 -> [0]. Tolera blob malformado -> []."""
    if blob[:5] == MAGIC_V1:
        return [KIND_PASSWORD]
    magic = blob[:5]
    if magic not in (MAGIC_V2, MAGIC_V3, MAGIC_V4) or len(blob) < 7:
        return []
    nslots = blob[6]
    if not (1 <= nslots <= _MAX_SLOTS):
        return []
    try:
        slots, _ = _parse_slots(blob, nslots, magic)
    except VaultError:
        return []
    return [_base_kind(s[0]) for s in slots]


# --------------------------------------------------------------------------- #
# Compatibilidade / API simples
# --------------------------------------------------------------------------- #
def encrypt(plaintext: str, password: str) -> bytes:
    """Cria um cofre RDBT4 com uma unica senha (API compativel)."""
    return new_vault(plaintext, password=password)


def decrypt(blob: bytes, password: str | None = None, *, keyfile: bytes | None = None,
            x25519_private: bytes | None = None) -> str:
    """Abre um cofre e devolve so o texto (API compativel)."""
    return open_vault(blob, password=password, keyfile=keyfile, x25519_private=x25519_private).text


def looks_like_vault(blob: bytes) -> bool:
    """True se os bytes comecam com um MAGIC de cofre (RDBT1/RDBT2/RDBT3/RDBT4)."""
    return blob[:5] in (MAGIC_V1, MAGIC_V2, MAGIC_V3, MAGIC_V4)


def is_vault_file(path: str) -> bool:
    """True se o arquivo em `path` e um cofre (checa o MAGIC, nao a extensao)."""
    try:
        with open(path, "rb") as fh:
            return looks_like_vault(fh.read(5))
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Legado RDBT1 (senha unica, scrypt) — leitura para migrar
# --------------------------------------------------------------------------- #
def _decrypt_v1(blob: bytes, password: str) -> str:
    if len(blob) < _HEADER_V1_LEN:
        raise VaultError("cofre RDBT1 truncado")
    if blob[5] != VERSION:
        raise VaultError(f"versao de cofre nao suportada: {blob[5]}")
    log2n, r, p = blob[6], blob[7], blob[8]
    _check_scrypt(log2n, r, p)
    salt, nonce = blob[9:25], blob[25:37]
    key = _scrypt(password.encode("utf-8", "surrogatepass"), salt, log2n, r, p)
    try:
        pt = AESGCM(key).decrypt(nonce, blob[_HEADER_V1_LEN:], blob[:_HEADER_V1_LEN])
    except InvalidTag:
        raise WrongPassword("senha incorreta ou conteudo adulterado") from None
    return pt.decode("utf-8", "surrogatepass")
