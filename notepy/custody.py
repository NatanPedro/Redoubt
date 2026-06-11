"""Custodia assinada + trilha de auditoria — "cada arquivo e evidencia".

Eleva a custodia de um SHA-256 nu (que qualquer um recalcula, logo nao PROVA nada)
para:

  1. ASSINATURA Ed25519 do conteudo — uma identidade por instalacao. Quem tiver a
     chave PUBLICA verifica que o arquivo nao mudou desde que voce assinou; uma
     assinatura `.sig` destacada e prova exportavel/forense.
  2. TRILHA DE AUDITORIA encadeada (hash-chain, append-only) dos eventos
     (abrir/salvar/selar/queimar/assinar): cada entrada inclui o hash da anterior,
     entao adulterar um evento passado QUEBRA a cadeia de forma detectavel.

Honestidade (modelo de ameaca): a chave privada fica em arquivo LOCAL (sem senha,
por escolha de uso). Quem tem a maquina pode assinar como voce — a assinatura prova
"veio DESTA instalacao e nao mudou", desde que a chave privada nao tenha vazado.
Tudo LOCAL, sem rede. Cripto pela lib `cryptography` (Ed25519). Sem Qt aqui.
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

_ORG, _APP = "Redoubt", "Redoubt"


def _data_dir() -> str:
    """Diretorio por-usuario p/ a identidade e a trilha (monkeypatchavel em testes)."""
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, _ORG, _APP)
    os.makedirs(d, exist_ok=True)
    return d


def _key_path() -> str:
    return os.path.join(_data_dir(), "identity.ed25519")


def _audit_path() -> str:
    return os.path.join(_data_dir(), "audit.log")


# --------------------------------------------------------------------------- #
# Identidade (par de chaves Ed25519 por instalacao)
# --------------------------------------------------------------------------- #
def load_or_create_key() -> Ed25519PrivateKey:
    p = _key_path()
    if os.path.exists(p):
        with open(p, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(p, "wb") as fh:
        fh.write(pem)
    try:
        os.chmod(p, 0o600)          # so o dono le (best-effort no Windows)
    except OSError:
        pass
    return key


def _public_raw() -> bytes:
    return load_or_create_key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_b64() -> str:
    """Chave PUBLICA (32 bytes) em base64 — compartilhe para outros verificarem."""
    return base64.b64encode(_public_raw()).decode()


def fingerprint() -> str:
    """Impressao digital curta da chave publica (SHA-256, 16 hex)."""
    return hashlib.sha256(_public_raw()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Assinar / verificar
# --------------------------------------------------------------------------- #
def sign(content: str) -> str:
    """Assina o conteudo com a chave privada local. Devolve a assinatura em base64."""
    sig = load_or_create_key().sign(content.encode("utf-8", "surrogatepass"))
    return base64.b64encode(sig).decode()


def verify(content: str, signature_b64: str, public_b64: str | None = None) -> bool:
    """Verifica a assinatura. Sem `public_b64`, usa a chave publica LOCAL."""
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        pub = (Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64, validate=True))
               if public_b64 else load_or_create_key().public_key())
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
