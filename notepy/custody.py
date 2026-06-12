"""Custodia assinada + trilha de auditoria — "cada arquivo e evidencia".

Eleva a custodia de um SHA-256 nu (que qualquer um recalcula, logo nao PROVA nada)
para:

  1. ASSINATURA Ed25519 do conteudo — uma identidade por instalacao. Quem tiver a
     chave PUBLICA verifica que o arquivo nao mudou desde que voce assinou; uma
     assinatura `.sig` destacada e prova exportavel/forense.
  2. TRILHA DE AUDITORIA encadeada (hash-chain, append-only) dos eventos
     (abrir/salvar/selar/queimar/assinar): cada entrada inclui o hash da anterior,
     entao adulterar um evento passado QUEBRA a cadeia de forma detectavel.

Identidade — duas formas (a privada NUNCA precisa estar em claro):
  - LEGADA (compat): `identity.ed25519` (PEM, sem senha).
  - PROTEGIDA (opt-in): a chave privada vive embrulhada num Cofre RDBT2 em
    `identity.rdbt` (mesmo `vault.py` do app: senha + arquivo-chave, multi-slot). A
    chave PUBLICA fica em claro em `identity.pub`, entao fingerprint/verificacao NAO
    pedem senha; so ASSINAR pede. A senha e cacheada em memoria por sessao (lazy).

Honestidade (modelo de ameaca): protegida, a privada so e util com a senha/arquivo-chave
(zero-knowledge — sem backdoor; perder a credencial = perder a identidade, mas a publica
exportada segue verificando o que ja foi assinado). Sem proteger, quem tem a maquina
assina como voce. Tudo LOCAL, sem rede. Cripto pela lib `cryptography` (Ed25519).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import vault

_ORG, _APP = "Redoubt", "Redoubt"

# Cache em memoria da chave privada destravada (por sessao). Lazy: so populado ao
# assinar com a senha certa, ou via unlock_identity(). Nunca tocado ao disco.
_session_key: Ed25519PrivateKey | None = None


class IdentityLocked(Exception):
    """A identidade esta protegida por senha; forneca a passphrase/arquivo-chave para assinar."""


class CustodyError(Exception):
    """Erro de custodia (ex.: chave publica local ausente/ilegivel)."""


def _data_dir() -> str:
    """Diretorio por-usuario p/ a identidade e a trilha (monkeypatchavel em testes)."""
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, _ORG, _APP)
    os.makedirs(d, exist_ok=True)
    return d


def _pem_path() -> str:
    return os.path.join(_data_dir(), "identity.ed25519")    # privada LEGADA (sem senha)


def _pub_path() -> str:
    return os.path.join(_data_dir(), "identity.pub")        # publica em CLARO (b64)


def _vault_path() -> str:
    return os.path.join(_data_dir(), "identity.rdbt")       # privada PROTEGIDA (cofre RDBT2)


def _audit_path() -> str:
    return os.path.join(_data_dir(), "audit.log")


def _atomic_write(path: str, data: bytes) -> None:
    """Escreve `data` de forma atomica: temp no mesmo dir + fsync + os.replace.
    Se algo falhar, remove o temp para nao deixar copia orfa (possivelmente sensivel) em disco."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        raise


def _secure_remove(path: str) -> None:
    """Sobrescreve o conteudo (best-effort) e remove. Em SSD/COW o overwrite nao garante
    apagamento fisico, mas reduz a janela de recuperacao da chave em claro. Propaga OSError
    do os.remove de proposito — o chamador verifica e faz rollback."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.write(os.urandom(size))
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    os.remove(path)


# --------------------------------------------------------------------------- #
# Identidade (par de chaves Ed25519 por instalacao)
# --------------------------------------------------------------------------- #
def is_protected() -> bool:
    """True se a chave privada esta embrulhada por senha (existe identity.rdbt)."""
    return os.path.exists(_vault_path())


def identity_has_orphan_pem() -> bool:
    """Estado INCONSISTENTE: identidade protegida (cofre) E um PEM nu (identity.ed25519)
    coexistindo. O PEM e uma copia em CLARO da chave — residuo de um proteger/desproteger
    interrompido (ex.: processo morto entre gravar o cofre e remover o PEM). O rollback de
    protect/unprotect previne isso no fluxo normal; isto detecta o residuo de uma interrupcao
    abrupta para a UI sinalizar e para a auto-limpeza no unlock."""
    return is_protected() and os.path.exists(_pem_path())


def _heal_orphan_pem(key: Ed25519PrivateKey) -> bool:
    """Se ha um PEM nu coexistindo com o cofre E ele e a MESMA chave de `key`, remove-o (com wipe),
    eliminando a copia em claro. So apaga apos confirmar que a chave publica bate — NUNCA remove uma
    chave diferente. Devolve True se limpou. Chamado no unlock, quando temos a chave real em maos."""
    pem = _pem_path()
    if not (is_protected() and os.path.exists(pem)):
        return False
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    try:
        with open(pem, "rb") as fh:
            orphan = serialization.load_pem_private_key(fh.read(), password=None)
        same = orphan.public_key().public_bytes(*raw) == key.public_key().public_bytes(*raw)
    except (ValueError, OSError, TypeError):
        return False
    if not same:
        return False                    # chave diferente: nao apaga (conservador)
    try:
        _secure_remove(pem)
        return True
    except OSError:
        return False


def _pub_b64_of(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _write_pub(pub_b64: str) -> None:
    with open(_pub_path(), "w", encoding="ascii") as fh:
        fh.write(pub_b64 + "\n")


def _new_key() -> Ed25519PrivateKey:
    """Gera uma identidade nova, salva como PEM LEGADO (sem senha) + publica em claro."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    _atomic_write(_pem_path(), pem)
    try:
        os.chmod(_pem_path(), 0o600)            # so o dono le (best-effort no Windows)
    except OSError:
        pass
    _write_pub(_pub_b64_of(key))
    return key


def _load_legacy() -> Ed25519PrivateKey | None:
    p = _pem_path()
    if not os.path.exists(p):
        return None
    with open(p, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def _open_protected(passphrase: str | None = None, *,
                    keyfile: bytes | None = None) -> Ed25519PrivateKey:
    """Abre o cofre da identidade e reconstroi a chave.
    Levanta vault.VaultError (WrongPassword/NotAVault/conteudo invalido) em qualquer falha."""
    with open(_vault_path(), "rb") as fh:
        blob = fh.read()
    raw_b64 = vault.open_vault(blob, password=passphrase, keyfile=keyfile).text  # VaultError se credencial errada
    try:
        raw = base64.b64decode(raw_b64, validate=True)
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (binascii.Error, ValueError) as exc:
        raise vault.VaultError("conteudo do cofre da identidade invalido") from exc


def _private_key(passphrase: str | None = None) -> Ed25519PrivateKey:
    """A chave privada. Protegida: usa o cache da sessao OU a passphrase; senao IdentityLocked.
    Nao protegida: carrega a legada ou cria uma nova."""
    global _session_key
    if is_protected():
        if _session_key is not None:
            return _session_key
        if passphrase is None:
            raise IdentityLocked("identidade protegida por senha")
        _session_key = _open_protected(passphrase)
        return _session_key
    return _load_legacy() or _new_key()


def load_or_create_key() -> Ed25519PrivateKey:
    """Compat: a chave da instalacao (sem pedir senha). Se protegida e sem cache, IdentityLocked."""
    return _private_key()


def unlock_identity(passphrase: str | None = None, *, keyfile: bytes | None = None) -> bool:
    """Destrava e cacheia a chave por esta sessao. Devolve False se a credencial estiver errada
    (ou o cofre estiver corrompido). Ao destravar, re-grava identity.pub a partir da chave REAL,
    corrigindo qualquer adulteracao da publica em claro (binding pub <-> chave)."""
    global _session_key
    if not is_protected():
        return True
    try:
        key = _open_protected(passphrase, keyfile=keyfile)
    except vault.VaultError:
        return False
    _session_key = key
    _write_pub(_pub_b64_of(key))
    _heal_orphan_pem(key)               # limpa PEM nu residual de operacao interrompida (mesma chave)
    return True


def lock_identity() -> None:
    """Esquece a chave cacheada (ex.: ao bloquear o app)."""
    global _session_key
    _session_key = None


def _public_raw() -> bytes:
    """Chave publica crua (32 bytes), SEM pedir senha. Fonte da verdade: a chave em cache (ou a
    legada, acessivel sem senha); so depende do identity.pub quando a privada esta TRAVADA — e
    valida o formato (nunca propaga binascii cru)."""
    if _session_key is not None:
        return _session_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not is_protected():
        key = _load_legacy() or _new_key()          # legado/novo: sem senha
        raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        _write_pub(base64.b64encode(raw).decode())
        return raw
    # Protegida e travada: depende da publica em claro. Valida; nunca crash cru.
    try:
        with open(_pub_path(), encoding="ascii") as fh:
            raw = base64.b64decode(fh.read().strip(), validate=True)
    except (OSError, binascii.Error, ValueError) as exc:
        raise CustodyError("chave publica (identity.pub) ausente ou ilegivel") from exc
    if len(raw) != 32:
        raise CustodyError("chave publica (identity.pub) com tamanho invalido")
    return raw


def public_key_b64() -> str:
    """Chave PUBLICA (32 bytes) em base64 — compartilhe para outros verificarem. Sem senha."""
    return base64.b64encode(_public_raw()).decode()


def fingerprint() -> str:
    """Impressao digital curta da chave publica (SHA-256, 16 hex). Sem senha."""
    return hashlib.sha256(_public_raw()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Proteger / destravar a identidade (opt-in, reusa o Cofre RDBT2)
# --------------------------------------------------------------------------- #
def protect_identity(passphrase: str | None = None, *, keyfile: bytes | None = None) -> None:
    """Protege a identidade ATUAL (preserva o fingerprint) embrulhando a chave num Cofre.

    Remove o PEM em claro. Levanta vault.VaultError se ja protegida ou sem credencial.
    """
    global _session_key
    if is_protected():
        raise vault.VaultError("identidade ja esta protegida (use add_identity_unlocker)")
    if not passphrase and not keyfile:
        raise vault.VaultError("forneca uma senha ou um arquivo-chave")
    key = _load_legacy() or _new_key()         # a chave atual — preserva a identidade
    raw = key.private_bytes(serialization.Encoding.Raw,
                            serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    blob = vault.new_vault(base64.b64encode(raw).decode(),
                           password=passphrase or None, keyfile=keyfile)
    _atomic_write(_vault_path(), blob)         # cofre gravado atomicamente
    _write_pub(_pub_b64_of(key))               # publica em claro

    # Remover a privada NUA e parte CRITICA: se falhar, faz ROLLBACK e NAO reporta sucesso
    # (senao o PEM em claro sobreviveria enquanto o app diz "protegida").
    if os.path.exists(_pem_path()):
        try:
            _secure_remove(_pem_path())        # sobrescreve + remove
        except OSError:
            pass
    if os.path.exists(_pem_path()):            # ainda la? remocao falhou (lock de AV/sync/backup)
        try:
            os.remove(_vault_path())           # rollback: desfaz a protecao parcial
        except OSError:
            pass
        raise vault.VaultError(
            "nao foi possivel remover a chave em claro (identity.ed25519) — feche programas "
            "que possam estar usando o arquivo (antivirus/sync/backup) e tente de novo")
    _session_key = key                         # so agora: protecao confirmada


def unprotect_identity(passphrase: str | None = None, *, keyfile: bytes | None = None) -> None:
    """Remove a proteção: volta a privada para PEM sem senha. Levanta WrongPassword se errar."""
    global _session_key
    if not is_protected():
        raise vault.VaultError("identidade nao esta protegida")
    key = _open_protected(passphrase, keyfile=keyfile)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    _atomic_write(_pem_path(), pem)
    try:
        os.chmod(_pem_path(), 0o600)
    except OSError:
        pass
    # Remover o cofre e critico (espelho do rollback de protect_identity): se falhar, NAO
    # deixa o PEM em claro coexistir com o cofre — desfaz o PEM e mantem a identidade protegida.
    try:
        _secure_remove(_vault_path())
    except OSError:
        pass
    if os.path.exists(_vault_path()):
        try:
            _secure_remove(_pem_path())
        except OSError:
            pass
        raise vault.VaultError(
            "nao foi possivel remover o cofre da identidade — feche programas que possam "
            "estar usando o arquivo (antivirus/sync/backup) e tente de novo")
    _write_pub(_pub_b64_of(key))
    _session_key = key


def add_identity_unlocker(passphrase: str | None = None, *, keyfile: bytes | None = None,
                          new_password: str | None = None, new_keyfile: bytes | None = None) -> None:
    """Adiciona uma senha/arquivo-chave EXTRA ao cofre da identidade (destrava com a credencial atual)."""
    if not is_protected():
        raise vault.VaultError("identidade nao esta protegida")
    if not new_password and not new_keyfile:
        raise vault.VaultError("forneca a nova senha ou o novo arquivo-chave")
    with open(_vault_path(), "rb") as fh:
        blob = fh.read()
    opened = vault.open_vault(blob, password=passphrase, keyfile=keyfile)
    slots = vault.add_unlocker(opened.key, opened.slots,
                               password=new_password, keyfile=new_keyfile)
    _atomic_write(_vault_path(), vault.reseal(opened.text, opened.key, slots))


def identity_unlockers() -> list[int]:
    """Tipos de destravador da identidade (0=senha, 1=arquivo-chave). [] se nao protegida."""
    if not is_protected():
        return []
    with open(_vault_path(), "rb") as fh:
        return vault.slot_kinds(fh.read())


# --------------------------------------------------------------------------- #
# Assinar / verificar
# --------------------------------------------------------------------------- #
def sign(content: str, passphrase: str | None = None) -> str:
    """Assina o conteudo com a chave privada local. Devolve a assinatura em base64.

    Se a identidade estiver protegida e nao houver chave em cache nem passphrase,
    levanta IdentityLocked — a UI deve pedir a senha e chamar unlock_identity() (ou
    passar `passphrase` aqui) e tentar de novo.
    """
    sig = _private_key(passphrase).sign(content.encode("utf-8", "surrogatepass"))
    return base64.b64encode(sig).decode()


def verify(content: str, signature_b64: str, public_b64: str | None = None) -> bool:
    """Verifica a assinatura. Sem `public_b64`, usa a chave publica LOCAL (sem senha)."""
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        pub = (Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64, validate=True))
               if public_b64 else Ed25519PublicKey.from_public_bytes(_public_raw()))
        pub.verify(sig, content.encode("utf-8", "surrogatepass"))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


# --------------------------------------------------------------------------- #
# Trilha de auditoria (hash-chain append-only)
# --------------------------------------------------------------------------- #
_CHAIN_FIELDS = ("ts", "event", "detail", "content_hash", "prev")


def _entry_hash(entry: dict) -> str:
    payload = json.dumps({k: entry.get(k, "") for k in _CHAIN_FIELDS},
                         sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def read_audit() -> list[dict]:
    p = _audit_path()
    if not os.path.exists(p):
        return []
    out: list[dict] = []
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def log_event(event: str, detail: str = "", content_hash: str = "",
              ts: str | None = None) -> dict:
    """Anexa um evento a trilha, encadeado no hash do anterior."""
    entries = read_audit()
    prev = entries[-1].get("hash", "") if entries else ""
    entry = {
        "ts": ts or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event, "detail": detail, "content_hash": content_hash, "prev": prev,
    }
    entry["hash"] = _entry_hash(entry)
    with open(_audit_path(), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def verify_chain() -> tuple[bool, int]:
    """Verifica a integridade da cadeia. Retorna (intacta, indice_da_quebra | -1)."""
    prev = ""
    for i, e in enumerate(read_audit()):
        if e.get("prev", "") != prev:
            return False, i
        if _entry_hash(e) != e.get("hash"):
            return False, i
        prev = e["hash"]
    return True, -1
