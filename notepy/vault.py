"""Cofre cifrado do Redoubt — guarda segredo de PROPOSITO (zero-knowledge).

Diferente da Sentinela (que *detecta* padrao), o Cofre nao adivinha nada: voce
DECLARA que o conteudo e segredo e ele e cifrado em repouso.

Cripto (formato RDBT3 — "envelope" / key-slots, estilo LUKS/age):
  - Uma CHAVE-DE-CONTEUDO (CK) aleatoria de 256 bits cifra o texto (AES-256-GCM).
  - Cada DESTRAVADOR (senha OU arquivo-chave) e um SLOT que "embrulha" a CK com uma
    chave derivada por KDF. Varias senhas/keyfiles independentes abrem o MESMO cofre;
    re-cifrar = trocar os slots (sem re-derivar tudo).
  - Zero-knowledge: nenhuma senha/keyfile e gravada. Sem backdoor nem recuperacao.

KDF por slot (RDBT3): o nibble ALTO do byte `kind` de cada slot diz qual KDF derivou
aquela KEK — 0=scrypt (legado), 1=**Argon2id** (padrao novo, *memory-hard*). Assim um
cofre pode ter slots scrypt (de um RDBT2 antigo) e slots Argon2id (novos) coexistindo,
cada um aberto com o seu KDF. O byte `kind` esta na AAD do slot — trocar o KDF quebra o
GCM (anti-downgrade). Novos slots usam Argon2id; cofres antigos continuam abrindo.

Formato RDBT3 (binario):
  [0:5]   MAGIC b"RDBT3"  (le tambem b"RDBT2" identico, e b"RDBT1" legado p/ migrar)
  [5]     versao (1)
  [6]     nslots (1..16)
  depois nslots SLOTS de 80 bytes cada:
    [0]     kind: nibble baixo = 0(senha)/1(arquivo-chave); nibble alto = KDF 0(scrypt)/1(argon2id)
    [1:4]   3 bytes de parametro do KDF:
              scrypt   -> (log2n, r, p)
              argon2id -> (iterations, memory_log2 [KiB], lanes)
    [4:20]  salt (16)
    [20:32] wrap_nonce (12)
    [32:80] CK embrulhada (48 = 32 + tag GCM)  — AAD = os 32 bytes do cabecalho do slot
  depois:
    content_nonce (12)
    content_ct (resto)  — AES-256-GCM(CK); AAD = todo o cabecalho + slots (anti-strip)
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC_V1 = b"RDBT1"
MAGIC_V2 = b"RDBT2"
MAGIC_V3 = b"RDBT3"
VERSION = 1
_KEY_LEN = 32          # AES-256 / tamanho da CK
_SALT_LEN = 16
_NONCE_LEN = 12
_HEADER_V1_LEN = 37    # 5 + 1 + 1 + 1 + 1 + 16 + 12
_SLOT_LEN = 80         # 1 + 3 + 16 + 12 + 48
_WRAPPED_LEN = 48      # CK (32) + tag GCM (16)
_MAX_SLOTS = 16

# Nibble baixo do byte `kind`: tipo de destravador.
KIND_PASSWORD = 0
KIND_KEYFILE = 1
# Nibble alto do byte `kind`: qual KDF derivou a KEK do slot.
KDF_SCRYPT = 0
KDF_ARGON2 = 1

# scrypt (legado: leitura de slots/cofres antigos e do RDBT1)
_DEFAULT_LOG2N = 15    # n = 2**15 (~32 MB)
_DEFAULT_R = 8
_DEFAULT_P = 1

# Argon2id (padrao novo). memory_cost = 2**MEMLOG2 KiB. 16 -> 64 MiB, t=3, 4 lanes:
# memory-hard, sub-segundo no desktop. Lidos do modulo em tempo de chamada (testes
# podem reduzir via monkeypatch para rodar rapido).
_DEFAULT_ARGON_T = 3
_DEFAULT_ARGON_MEMLOG2 = 16
_DEFAULT_ARGON_LANES = 4

# Orcamento anti-DoS. Sem isto, um .rdbt forjado com parametros no teto (scrypt r/p ou Argon t
# multiplicam o custo) e ate _MAX_SLOTS slots — todos derivados em serie por open_vault ANTES do
# GCM — congelaria a UI por minutos e estouraria memoria. Limitamos o custo POR SLOT e o AGREGADO
# dos slots que casam a credencial num open. Constantes FIXAS (nao derivam dos defaults, que os
# testes reduzem por monkeypatch).
_MAX_KDF_MEM = 128 * 1024 * 1024     # pico de memoria por derivacao (guarda anti-OOM): 128 MiB
# "Trabalho" ~ proporcional ao TEMPO de derivacao (scrypt ~ N*r*p; argon ~ memoria_KiB*iteracoes).
# E uma APROXIMACAO: o tempo do Argon por unidade cresce com a memoria (banda/cache), entao o pior
# caso real fica ACIMA de uma extrapolacao linear. Medido empiricamente: o teto agregado admite ~4
# slots no maximo por-slot, derivados EM SERIE = ~5s de pico e ~128 MiB (nao os "poucos segundos" de
# 16 slots default leves). O objetivo e FECHAR o DoS (de ~minutos/512 MiB para ~5s/128 MiB).
_MAX_KDF_WORK = 1 << 20              # custo por slot (memoria <=128 MiB; ~1-1.3s no teto)
_MAX_TOTAL_KDF_WORK = 1 << 22       # soma dos slots derivados num open (cabe 16 destravadores default)


class VaultError(Exception):
    """Erro generico do cofre."""


class NotAVault(VaultError):
    """Os bytes nao sao um cofre .rdbt valido (MAGIC ausente)."""


class WrongPassword(VaultError):
    """Credencial incorreta OU conteudo adulterado (verificacao GCM falhou)."""


@dataclass
class Opened:
    """Resultado de abrir um cofre: texto + a chave-de-conteudo e os slots crus,
    para re-selar PRESERVANDO todos os destravadores (cada slot carrega o seu KDF)."""
    text: str
    key: bytes
    slots: list[bytes]


# --------------------------------------------------------------------------- #
# KDF / material
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
    return 128 * (1 << log2n) * r          # bytes (~128 * N * r)


def _argon_mem(memlog2: int) -> int:
    return (1 << memlog2) * 1024           # bytes (memory_cost em KiB)


def _scrypt_work(log2n: int, r: int, p: int) -> int:
    return (1 << log2n) * r * p             # ~ N*r*p (proporcional ao tempo do scrypt)


def _argon_work(memlog2: int, t: int) -> int:
    return (1 << memlog2) * t               # ~ memoria(KiB) * iteracoes (proporcional ao tempo)


def _check_scrypt(log2n: int, r: int, p: int) -> None:
    # Anti-bomba/DoS: limita os parametros E o custo. Bound por-parametro NAO basta — r MULTIPLICA
    # a memoria (~128*N*r) e p o trabalho; (18,16,16) passava e custava ~512 MiB / dezenas de seg.
    if not (1 <= log2n <= 18 and 1 <= r <= 16 and 1 <= p <= 4):
        raise VaultError(f"parametros scrypt fora dos limites (n=2^{log2n}, r={r}, p={p})")
    if _scrypt_mem(log2n, r) > _MAX_KDF_MEM or _scrypt_work(log2n, r, p) > _MAX_KDF_WORK:
        raise VaultError(f"custo scrypt excede o teto (~{_scrypt_mem(log2n, r) >> 20} MiB)")


def _check_argon(t: int, memlog2: int, lanes: int) -> None:
    # Idem: memory_cost = 2^memlog2 KiB; t multiplica o trabalho. memory_cost >= 8*lanes garantido
    # (memlog2>=10 -> 1 MiB >> 8*8). Mesmo teto de memoria/custo do scrypt.
    if not (1 <= t <= 8 and 10 <= memlog2 <= 17 and 1 <= lanes <= 8):
        raise VaultError(f"parametros Argon2id fora dos limites (t={t}, mem=2^{memlog2} KiB, lanes={lanes})")
    if _argon_mem(memlog2) > _MAX_KDF_MEM or _argon_work(memlog2, t) > _MAX_KDF_WORK:
        raise VaultError(f"custo Argon2id excede o teto (~{_argon_mem(memlog2) >> 20} MiB)")


def _slot_kdf_work(slot: bytes) -> float:
    """Custo estimado (MiB x passagens) de derivar a KEK deste slot, sem deriva-la. 0.0 se os
    parametros forem invalidos (o slot sera PULADO em open_vault, entao nao soma ao orcamento)."""
    kdf, a, b, c = _kdf_of(slot[0]), slot[1], slot[2], slot[3]
    try:
        if kdf == KDF_SCRYPT:
            _check_scrypt(a, b, c)
            return _scrypt_work(a, b, c)
        if kdf == KDF_ARGON2:
            _check_argon(a, b, c)
            return _argon_work(b, a)
    except VaultError:
        return 0.0
    return 0.0


def _material(kind: int, secret) -> bytes:
    """Material que entra no KDF: senha em utf-8; arquivo-chave -> sha256 (pode ser grande)."""
    if kind == KIND_PASSWORD:
        return secret.encode("utf-8", "surrogatepass") if isinstance(secret, str) else bytes(secret)
    return hashlib.sha256(bytes(secret)).digest()


def _derive_kek(kind_byte: int, secret, p1: int, p2: int, p3: int, salt: bytes) -> bytes:
    """Deriva a KEK do slot pelo KDF indicado no nibble alto de `kind_byte`. Valida os
    parametros antes (anti-bomba). Levanta VaultError se o KDF/parametros forem invalidos."""
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
# Slots  (novos slots usam Argon2id)
# --------------------------------------------------------------------------- #
def _make_slot(ck: bytes, base_kind: int, secret) -> bytes:
    """Cria um slot novo embrulhando `ck` com Argon2id (padrao RDBT3). Le os parametros
    padrao do modulo em tempo de chamada (testes podem reduzir via monkeypatch)."""
    t, memlog2, lanes = _DEFAULT_ARGON_T, _DEFAULT_ARGON_MEMLOG2, _DEFAULT_ARGON_LANES
    salt = os.urandom(_SALT_LEN)
    wrap_nonce = os.urandom(_NONCE_LEN)
    kind_byte = base_kind | (KDF_ARGON2 << 4)
    head = bytes([kind_byte, t, memlog2, lanes]) + salt + wrap_nonce   # 32 bytes (AAD do slot)
    kek = _argon2id(_material(base_kind, secret), salt, t, memlog2, lanes)
    wrapped = AESGCM(kek).encrypt(wrap_nonce, ck, head)                # 48 bytes
    return head + wrapped


def make_password_slot(ck: bytes, password: str) -> bytes:
    if not password:
        raise VaultError("senha-mestra vazia")
    return _make_slot(ck, KIND_PASSWORD, password)


def make_keyfile_slot(ck: bytes, keyfile: bytes) -> bytes:
    if not keyfile:
        raise VaultError("arquivo-chave vazio")
    return _make_slot(ck, KIND_KEYFILE, keyfile)


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
    header = bytes([*MAGIC_V3, VERSION, len(slots)])
    body = b"".join(slots)
    aad = header + body                                          # anti-strip de slots
    content_nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(ck).encrypt(content_nonce, plaintext.encode("utf-8", "surrogatepass"), aad)
    return header + body + content_nonce + ct


def new_vault(plaintext: str, *, password: str | None = None,
              keyfile: bytes | None = None) -> bytes:
    """Cria um cofre RDBT3 novo (Argon2id) com os destravadores dados (>=1)."""
    ck = generate_key()
    slots = add_unlocker(ck, [], password=password, keyfile=keyfile)
    return _assemble(ck, slots, plaintext)


def reseal(plaintext: str, key: bytes, slots: list[bytes]) -> bytes:
    """Re-cifra o conteudo sob a MESMA CK e slots (preserva todos os destravadores e seus KDFs)."""
    return _assemble(key, slots, plaintext)


def open_vault(blob: bytes, *, password: str | None = None,
               keyfile: bytes | None = None) -> Opened:
    """Abre um cofre (RDBT3/RDBT2 ou RDBT1 legado). Levanta NotAVault/WrongPassword/VaultError.

    O KDF de cada slot vem do nibble alto do byte `kind` (scrypt OU Argon2id), entao slots
    legados (scrypt) e novos (Argon2id) convivem no mesmo cofre."""
    if blob[:5] == MAGIC_V1:
        text = _decrypt_v1(blob, password or "")
        ck = generate_key()                                     # migra em memoria p/ RDBT3 (Argon2id)
        return Opened(text, ck, [make_password_slot(ck, password or "")])
    if blob[:5] not in (MAGIC_V2, MAGIC_V3):
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

    def _matches(s: bytes) -> bool:
        kb = _base_kind(s[0])
        return ((kb == KIND_PASSWORD and password is not None)
                or (kb == KIND_KEYFILE and keyfile is not None))

    # Anti-DoS: recusa ANTES de derivar se o custo agregado dos slots que casam a credencial
    # passar do orcamento. Um .rdbt forjado (params no teto x ate 16 slots, derivados em serie)
    # nunca chega a travar a UI — falha instantaneo aqui.
    if sum(_slot_kdf_work(s) for s in slots if _matches(s)) > _MAX_TOTAL_KDF_WORK:
        raise VaultError("custo de KDF agregado excede o orcamento (possivel cofre malicioso)")

    # Derivacao EM SERIE (um slot por vez): o pico de memoria e o de UMA derivacao (<=_MAX_KDF_MEM),
    # nao nslots*_MAX_KDF_MEM — e o que fecha o OOM. Se algum dia paralelizar, rever esta garantia.
    ck = None
    for slot in slots:
        if not _matches(slot):
            continue
        secret = password if _base_kind(slot[0]) == KIND_PASSWORD else keyfile
        # Slot com KDF desconhecido / params invalidos / KEK errada e PULADO (nao fatal): preserva
        # a coexistencia multi-slot e a forward-compat (outro slot valido ainda abre o cofre).
        try:
            kek = _derive_kek(slot[0], secret, slot[1], slot[2], slot[3], slot[4:20])
            ck = AESGCM(kek).decrypt(slot[20:32], slot[32:80], slot[:32])
            break
        except (VaultError, InvalidTag):
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
    """Tipos de slot do cofre (0=senha, 1=keyfile). RDBT1 -> [0]. Util p/ a UI.
    Mascarado para o nibble baixo (o nibble alto e o KDF, irrelevante para a UI)."""
    if blob[:5] == MAGIC_V1:
        return [KIND_PASSWORD]
    if blob[:5] not in (MAGIC_V2, MAGIC_V3) or len(blob) < 7:
        return []
    nslots = blob[6]
    if not (1 <= nslots <= _MAX_SLOTS) or len(blob) < 7 + _SLOT_LEN * nslots:
        return []
    return [blob[7 + i * _SLOT_LEN] & 0x0F for i in range(nslots)]


# --------------------------------------------------------------------------- #
# Compatibilidade / API simples
# --------------------------------------------------------------------------- #
def encrypt(plaintext: str, password: str) -> bytes:
    """Cria um cofre RDBT3 com uma unica senha (API compativel)."""
    return new_vault(plaintext, password=password)


def decrypt(blob: bytes, password: str | None = None, *, keyfile: bytes | None = None) -> str:
    """Abre um cofre e devolve so o texto (API compativel)."""
    return open_vault(blob, password=password, keyfile=keyfile).text


def looks_like_vault(blob: bytes) -> bool:
    """True se os bytes comecam com um MAGIC de cofre (RDBT1/RDBT2/RDBT3)."""
    return blob[:5] in (MAGIC_V1, MAGIC_V2, MAGIC_V3)


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
