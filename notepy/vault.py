"""Cofre cifrado do Redoubt — guarda segredo de PROPOSITO (zero-knowledge).

Diferente da Sentinela (que *detecta* padrao), o Cofre nao adivinha nada: voce
DECLARA que o conteudo e segredo e ele e cifrado em repouso. Vale para qualquer
texto, inclusive senha de conta que nao tem padrao nenhum.

Cripto:
  - Cifragem AUTENTICADA: AES-256-GCM (esconde E detecta adulteracao).
  - Derivacao de chave: scrypt (memory-hard, resistente a brute-force por GPU),
    nativo da lib `cryptography` (sem dependencia extra).
  - Zero-knowledge: a senha-mestra NUNCA e gravada. Errou/esqueceu = dado perdido.
    Nao ha backdoor nem recuperacao — por design.

Formato do arquivo .rdbt (binario):
  [0:5]   MAGIC  b"RDBT1"
  [5]     versao (1)
  [6]     log2(n) do scrypt   (n = 2**log2n)
  [7]     r do scrypt
  [8]     p do scrypt
  [9:25]  salt   (16 bytes, aleatorio por arquivo)
  [25:37] nonce  (12 bytes, aleatorio por gravacao)
  [37:]   ciphertext + tag GCM
O header inteiro (0:37) entra como dados autenticados (AAD): adulterar
parametros/salt/nonce quebra a verificacao.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"RDBT1"
VERSION = 1
_KEY_LEN = 32          # AES-256
_SALT_LEN = 16
_NONCE_LEN = 12
_HEADER_LEN = 37       # 5 + 1 + 1 + 1 + 1 + 16 + 12

# Parametros padrao do scrypt: n=2**15 (~32 MB), r=8, p=1 — bom para uso interativo.
_DEFAULT_LOG2N = 15
_DEFAULT_R = 8
_DEFAULT_P = 1


class VaultError(Exception):
    """Erro generico do cofre."""


class NotAVault(VaultError):
    """Os bytes nao sao um arquivo .rdbt valido (MAGIC ausente)."""


class WrongPassword(VaultError):
    """Senha incorreta OU conteudo adulterado (a verificacao GCM falhou)."""


def _derive_key(password: str, salt: bytes, log2n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=_KEY_LEN, n=2 ** log2n, r=r, p=p)
    return kdf.derive(password.encode("utf-8", "surrogatepass"))


def looks_like_vault(blob: bytes) -> bool:
    """True se os bytes comecam com o MAGIC do .rdbt."""
    return blob[:len(MAGIC)] == MAGIC


def is_vault_file(path: str) -> bool:
    """True se o arquivo em `path` e um cofre .rdbt (checa o MAGIC, nao a extensao)."""
    try:
        with open(path, "rb") as fh:
            return looks_like_vault(fh.read(len(MAGIC)))
    except OSError:
        return False


def encrypt(plaintext: str, password: str) -> bytes:
    """Cifra `plaintext` com `password` e devolve o blob .rdbt completo."""
    if not password:
        raise VaultError("senha-mestra vazia")
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    header = bytes([*MAGIC, VERSION, _DEFAULT_LOG2N, _DEFAULT_R, _DEFAULT_P]) + salt + nonce
    key = _derive_key(password, salt, _DEFAULT_LOG2N, _DEFAULT_R, _DEFAULT_P)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8", "surrogatepass"), header)
    return header + ct


def decrypt(blob: bytes, password: str) -> str:
    """Decifra um blob .rdbt. Levanta NotAVault / WrongPassword / VaultError."""
    if not looks_like_vault(blob):
        raise NotAVault("nao e um arquivo .rdbt (MAGIC ausente)")
    if len(blob) < _HEADER_LEN:
        raise VaultError("arquivo .rdbt truncado")
    version = blob[5]
    if version != VERSION:
        raise VaultError(f"versao de cofre nao suportada: {version}")
    log2n, r, p = blob[6], blob[7], blob[8]
    # Defesa contra .rdbt malicioso: um log2n grande (ex.: 63) faria o scrypt
    # alocar petabytes e travar/derrubar o app. Limita os parametros do KDF.
    if not (1 <= log2n <= 18 and 1 <= r <= 16 and 1 <= p <= 16):
        raise VaultError(f"parametros de KDF fora dos limites (n=2^{log2n}, r={r}, p={p})")
    salt = blob[9:25]
    nonce = blob[25:37]
    header = blob[:_HEADER_LEN]
    ct = blob[_HEADER_LEN:]
    key = _derive_key(password, salt, log2n, r, p)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, header)
    except InvalidTag:
        raise WrongPassword("senha incorreta ou conteudo adulterado") from None
    return plaintext.decode("utf-8", "surrogatepass")
