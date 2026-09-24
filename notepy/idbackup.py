"""Backup e restauracao da IDENTIDADE do Redoubt — nucleo puro, sem Qt.

Por que isto existe: a identidade Ed25519 desta instalacao e um arquivo de ~119 bytes no
diretorio de dados (`%APPDATA%\\Redoubt\\Redoubt` no Windows, `~/.local/share/Redoubt/Redoubt` no
Linux): `identity.ed25519`. E ela que assina o `RELEASE.json` de cada
release, os selos `.rdbt-seal` e as ancoras da trilha. Os verificadores standalone
(`verify_release.py` / `verify_seal.py`) tem a chave PUBLICA do autor **embutida**, entao:

  - perder a privada NAO invalida o que ja foi assinado (a publica continua publicada);
  - mas ninguem consegue mais assinar como aquele fingerprint. Um release novo, assinado por
    uma chave nova, e indistinguivel — de fora — de uma falsificacao. "Confie em mim, troquei
    de chave" e exatamente o que um atacante diria.

A rotacao PLANEJADA (assinar, com a chave antiga, uma declaracao que nomeia a nova) so e
possivel enquanto a chave antiga existe. Depois da perda, essa porta fecha. Logo: backup.

Formato do pacote: **RDBT-IDBAK1** — um JSON com as privadas em base64, embrulhado num Cofre
`.rdbt` (o mesmo `vault.py` do app: AES-256-GCM + Argon2id, senha e/ou arquivo-chave,
multi-slot). O arquivo e um cofre normal, so com extensao propria (`.rdbtbak`) para nao cair
na associacao de duplo-clique do instalador — abrir o backup no editor mostraria as privadas
em claro na tela.

Honestidade: e *zero-knowledge*. Esquecer a credencial do backup equivale a perder o backup.
Use senha forte **e** arquivo-chave, e guarde a credencial fora da maquina.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import custody, vault

FORMAT = "RDBT-IDBAK1"

_RAW_PRIV = (serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
             serialization.NoEncryption())
_RAW_PUB = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class BackupError(Exception):
    """Erro de backup/restauracao da identidade (mensagem amigavel, nunca vaza chave)."""


def _fp(pub_raw: bytes) -> str:
    """Fingerprint curto, igual ao da custodia: sha256(pub)[:16]."""
    return hashlib.sha256(pub_raw).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Coletar a identidade LOCAL
# --------------------------------------------------------------------------- #
def local_identity_exists() -> bool:
    """True se ja existe identidade Ed25519 nesta instalacao. READ-ONLY: nao cria nada
    (diferente de `custody.load_or_create_key`, que materializaria uma chave nova)."""
    return (custody.is_protected()
            or os.path.isfile(custody._pem_path())
            or os.path.isfile(custody._pub_path()))


def collect_local(passphrase: str | None = None, *, keyfile: bytes | None = None,
                  recipient_passphrase: str | None = None,
                  recipient_keyfile: bytes | None = None,
                  now: str | None = None) -> dict:
    """Monta o payload de backup a partir da instalacao local.

    Inclui a privada Ed25519 (obrigatoria) e a privada X25519 de destinatario (se existir —
    perde-la significa perder o acesso a todo cofre que selaram para voce). Levanta
    BackupError se nao houver identidade, ou se a credencial estiver errada.

    X25519 PROTEGIDA e travada exige `recipient_passphrase`/`recipient_keyfile`: sem eles o
    backup ERRA em vez de sair sem a chave — quem seguiu a recomendacao de proteger a chave
    ficaria, em silencio, sem backup justamente dela.
    """
    if not local_identity_exists():
        raise BackupError(
            "nenhuma identidade local encontrada — nada a copiar (assine algo no Redoubt "
            "primeiro, ou aponte o diretorio de dados correto)")
    if custody.is_protected():
        if not custody.unlock_identity(passphrase, keyfile=keyfile):
            raise BackupError("credencial da identidade incorreta (ela esta protegida por senha)")
    try:
        ed = custody.load_or_create_key()          # aqui ja destravada (ou legada em claro)
    except custody.IdentityLocked as exc:
        raise BackupError("identidade protegida: forneca a senha/arquivo-chave dela") from exc
    ed_raw = ed.private_bytes(*_RAW_PRIV)
    ed_fp = _fp(ed.public_key().public_bytes(*_RAW_PUB))

    x_raw = x_fp = None
    if custody.recipient_exists():
        if not custody.recipient_unlocked():
            if not recipient_passphrase and not recipient_keyfile:
                raise BackupError(
                    "a chave de destinatario (X25519) esta protegida: forneca a senha/arquivo-chave "
                    "dela — sem isso o backup sairia SEM a chave que abre os cofres selados para voce")
            if not custody.unlock_recipient(recipient_passphrase, keyfile=recipient_keyfile):
                raise BackupError("credencial da chave de destinatario (X25519) incorreta")
        try:
            x_raw = custody.recipient_private_bytes()
        except custody.CustodyError:
            # Chave de destinatario ILEGIVEL/corrompida (nao protegida — essa ja foi destravada
            # acima): seguimos com a Ed25519 e o chamador avisa. Nunca deixar a falha de uma chave
            # secundaria abortar o backup da principal.
            x_raw = None
        if x_raw:
            x_fp = _fp(X25519PrivateKey.from_private_bytes(x_raw).public_key().public_bytes(*_RAW_PUB))

    return {
        "format": FORMAT,
        "created_at": now or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ed25519_private": base64.b64encode(ed_raw).decode(),
        "ed25519_fingerprint": ed_fp,
        "x25519_private": base64.b64encode(x_raw).decode() if x_raw else None,
        "x25519_fingerprint": x_fp,
    }


# --------------------------------------------------------------------------- #
# Escrever / ler o pacote cifrado
# --------------------------------------------------------------------------- #
def make_blob(payload: dict, *, password: str | None = None,
              keyfile: bytes | None = None) -> bytes:
    """Embrulha o payload num Cofre. Exige credencial (sem ela nao ha backup cifrado)."""
    if not password and not keyfile:
        raise BackupError("forneca uma senha e/ou um arquivo-chave para cifrar o backup")
    texto = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return vault.new_vault(texto, password=password or None, keyfile=keyfile)


def open_blob(blob: bytes, *, password: str | None = None,
              keyfile: bytes | None = None) -> dict:
    """Abre um pacote de backup e valida o formato. Credencial errada -> BackupError."""
    try:
        texto = vault.open_vault(blob, password=password, keyfile=keyfile).text
    except vault.WrongPassword as exc:
        raise BackupError("credencial do backup incorreta") from exc
    except vault.VaultError as exc:
        raise BackupError(f"pacote de backup invalido: {exc}") from exc
    try:
        payload = json.loads(texto)
    except (json.JSONDecodeError, ValueError) as exc:
        raise BackupError("conteudo do backup nao e JSON valido") from exc
    if not isinstance(payload, dict) or payload.get("format") != FORMAT:
        raise BackupError(f"nao e um backup de identidade do Redoubt (esperado {FORMAT})")
    if not payload.get("ed25519_private"):
        raise BackupError("backup sem a chave Ed25519")
    return payload


def payload_keys(payload: dict) -> tuple[bytes, bytes | None]:
    """Extrai (ed25519_raw, x25519_raw|None) validando tamanho. NUNCA logue o retorno."""
    def _raw(campo: str, valor: str) -> bytes:
        try:
            raw = base64.b64decode(valor, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BackupError(f"{campo} do backup nao e base64 valido") from exc
        if len(raw) != 32:
            raise BackupError(f"{campo} do backup com tamanho invalido ({len(raw)} bytes)")
        return raw

    ed = _raw("chave Ed25519", payload["ed25519_private"])
    x = _raw("chave X25519", payload["x25519_private"]) if payload.get("x25519_private") else None
    return ed, x


def verify_blob(blob: bytes, *, password: str | None = None, keyfile: bytes | None = None,
                expected_ed_fingerprint: str | None = None) -> dict:
    """PROVA que o pacote recem-criado abre e devolve a MESMA identidade.

    Um backup nao verificado e so uma esperanca: e o mesmo principio do cofre da identidade —
    so prometemos o backup depois de reabri-lo e conferir o fingerprint derivado da chave.
    """
    payload = open_blob(blob, password=password, keyfile=keyfile)
    ed_raw, _ = payload_keys(payload)
    fp = _fp(Ed25519PrivateKey.from_private_bytes(ed_raw).public_key().public_bytes(*_RAW_PUB))
    if fp != payload.get("ed25519_fingerprint"):
        raise BackupError("backup inconsistente: o fingerprint declarado nao corresponde a chave")
    if expected_ed_fingerprint and fp != expected_ed_fingerprint:
        raise BackupError(
            f"backup NAO corresponde a identidade local (backup {fp}, "
            f"local {expected_ed_fingerprint})")
    return payload


def summary(payload: dict) -> str:
    """Resumo legivel do pacote — so metadados, JAMAIS material de chave."""
    x = payload.get("x25519_fingerprint") or "(ausente)"
    return (f"formato: {payload.get('format')}\n"
            f"criado em: {payload.get('created_at')}\n"
            f"identidade Ed25519 (assina): {payload.get('ed25519_fingerprint')}\n"
            f"chave X25519 (destinatario): {x}")


# --------------------------------------------------------------------------- #
# Restaurar
# --------------------------------------------------------------------------- #
def _fingerprint_in_dir(data_dir: str) -> str | None:
    """Fingerprint da identidade que JA esta em `data_dir`, ou None. Read-only: nao cria nada
    e nao depende do `_data_dir()` global (a restauracao pode apontar para outro diretorio)."""
    pub = os.path.join(data_dir, "identity.pub")
    if os.path.isfile(pub):
        try:
            with open(pub, encoding="ascii") as fh:
                return _fp(base64.b64decode(fh.read().strip(), validate=True))
        except (OSError, binascii.Error, ValueError):
            return None
    pem = os.path.join(data_dir, "identity.ed25519")
    if os.path.isfile(pem):
        try:
            with open(pem, "rb") as fh:
                key = serialization.load_pem_private_key(fh.read(), password=None)
            return _fp(key.public_key().public_bytes(*_RAW_PUB))
        except (OSError, ValueError, TypeError):
            return None
    return None


def _identity_present(data_dir: str, *, with_recipient: bool = False) -> bool:
    """Ha identidade em `data_dir`? Com `with_recipient`, uma chave de destinatario (em claro ou
    protegida) tambem conta — restaurar a X25519 por cima dela a substitui, igual a Ed25519."""
    nomes = ["identity.ed25519", "identity.rdbt", "identity.pub"]
    if with_recipient:
        nomes += ["recipient.x25519", "recipient.rdbt"]
    return any(os.path.isfile(os.path.join(data_dir, n)) for n in nomes)


def restore(payload: dict, data_dir: str, *, force: bool = False) -> list[str]:
    """Grava as chaves do backup em `data_dir`. Devolve os nomes escritos.

    RECUSA sobrescrever uma identidade existente sem `force` — trocar identidade em silencio e
    exatamente o acidente que o backup deveria evitar (voce perderia a chave que assina hoje).
    A mensagem mostra os DOIS fingerprints para a comparacao ser consciente.
    """
    ed_raw, x_raw = payload_keys(payload)
    if _identity_present(data_dir, with_recipient=bool(x_raw)) and not force:
        atual = _fingerprint_in_dir(data_dir) or "(ilegivel)"
        raise BackupError(
            f"ja existe uma identidade em {data_dir} (fingerprint {atual}); o backup traz "
            f"{payload.get('ed25519_fingerprint')}. Restaurar por cima SUBSTITUI a chave atual — "
            f"confirme que e isso que voce quer e repita com force/--force")

    os.makedirs(data_dir, exist_ok=True)
    ed = Ed25519PrivateKey.from_private_bytes(ed_raw)
    pem = ed.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
    escritos: list[str] = []

    def _grava(nome: str, dados: bytes, sensivel: bool) -> None:
        caminho = os.path.join(data_dir, nome)
        custody._atomic_write(caminho, dados)       # temp + fsync + replace (mesmo do app)
        if sensivel:
            try:
                os.chmod(caminho, 0o600)            # so o dono le (best-effort no Windows)
            except OSError:
                pass
        escritos.append(nome)

    _grava("identity.ed25519", pem, True)
    _grava("identity.pub",
           (base64.b64encode(ed.public_key().public_bytes(*_RAW_PUB)).decode() + "\n").encode("ascii"),
           False)
    if x_raw:
        # Mesma armadilha do identity.rdbt, na chave de destinatario: um `recipient.rdbt` ANTIGO
        # faria `recipient_is_protected()` vencer — o app seguiria com a chave VELHA e a restaurada
        # viraria "copia em claro orfa". Remove-lo ANTES de gravar: se falhar, nada da X25519 foi
        # tocado (sem estado misto). A `recipient.pub` e regravada a partir da privada restaurada:
        # a antiga anunciaria o fingerprint velho (e selar "para voce" iria para a chave errada).
        velho_x = os.path.join(data_dir, "recipient.rdbt")
        removeu_x = False
        if os.path.isfile(velho_x):
            try:
                custody._force_remove(velho_x)
                removeu_x = True
            except OSError as exc:
                raise BackupError(
                    f"a identidade Ed25519 foi restaurada, mas nao consegui remover o cofre da chave "
                    f"de destinatario anterior ({velho_x}): {exc}. A chave X25519 NAO foi restaurada "
                    f"— remova-o a mao e repita o restore com --force") from exc
        x_pub = X25519PrivateKey.from_private_bytes(x_raw).public_key().public_bytes(*_RAW_PUB)
        _grava("recipient.x25519", x_raw, True)
        _grava("recipient.pub", (base64.b64encode(x_pub).decode() + "\n").encode("ascii"), False)
        if removeu_x:
            escritos.append("recipient.rdbt (removido: cofre da chave de destinatario ANTERIOR)")

    # A restauracao devolve a forma LEGADA (PEM em claro); proteger de novo e um passo consciente
    # do usuario, no proprio app. Mas um `identity.rdbt` ANTIGO nao pode ficar: `is_protected()`
    # venceria e o app usaria a chave velha, ignorando o que acabamos de restaurar — a restauracao
    # seria silenciosamente inutil. So chegamos aqui com force (a checagem acima ja barrou o resto).
    velho_cofre = os.path.join(data_dir, "identity.rdbt")
    if os.path.isfile(velho_cofre):
        try:
            os.remove(velho_cofre)
            escritos.append("identity.rdbt (removido: cofre da identidade ANTERIOR)")
        except OSError as exc:
            raise BackupError(
                f"a chave foi restaurada, mas nao consegui remover o cofre da identidade anterior "
                f"({velho_cofre}): {exc}. Enquanto ele existir, o Redoubt usara a chave ANTIGA — "
                f"remova-o a mao e reabra o app") from exc
    return escritos
