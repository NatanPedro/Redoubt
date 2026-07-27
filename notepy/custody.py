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

Chave de DESTINATARIO (X25519) — separada da Ed25519 e tambem protegivel:
  - EM CLARO (default/legado): `recipient.x25519` (raw 32 bytes).
  - PROTEGIDA (opt-in): embrulhada num Cofre em `recipient.rdbt`, com a publica em claro em
    `recipient.pub` — exportar a sua chave e SELAR para alguem seguem sem senha; so ABRIR um
    cofre selado para voce pede a credencial (1x por sessao).

Honestidade (modelo de ameaca): protegida, a privada so e util com a senha/arquivo-chave
(zero-knowledge — sem backdoor; perder a credencial = perder a identidade, mas a publica
exportada segue verificando o que ja foi assinado). Sem proteger, quem tem a maquina
assina como voce — e, no caso da X25519, decifra o que selaram para voce. Tudo LOCAL, sem
rede. Cripto pela lib `cryptography` (Ed25519 + X25519).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import vault

_ORG, _APP = "Redoubt", "Redoubt"

# Cache em memoria da chave privada destravada (por sessao). Lazy: so populado ao
# assinar com a senha certa, ou via unlock_identity(). Nunca tocado ao disco.
_session_key: Ed25519PrivateKey | None = None


class IdentityLocked(Exception):
    """A identidade esta protegida por senha; forneca a passphrase/arquivo-chave para assinar."""


class CustodyError(Exception):
    """Erro de custodia (ex.: chave publica local ausente/ilegivel)."""


class IdentityClearCopyRemains(Exception):
    """A protecao da identidade FOI concluida (cofre gravado e verificado), mas o PEM em claro nao
    pudo ser removido e continua no disco. Nao e falha de protecao — e aviso com acao pendente (por
    isso nao herda de VaultError: a UI nao deve dizer "nao foi possivel proteger")."""


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


# --------------------------------------------------------------------------- #
# Identidade de DESTINATARIO (X25519) — cifrar-PARA / abrir o que selaram pra voce.
# Separada da Ed25519 (que e p/ ASSINAR): aqui e p/ CIFRAR (curva de troca de chaves).
#
# Duas formas, espelhando a identidade Ed25519:
#   - EM CLARO (default/legado): `recipient.x25519` (raw 32 bytes).
#   - PROTEGIDA (opt-in): a privada vive embrulhada num Cofre em `recipient.rdbt`; a
#     PUBLICA fica em claro em `recipient.pub`, entao EXPORTAR a sua chave e SELAR para
#     alguem NAO pedem senha — so ABRIR um cofre selado para voce pede (1x por sessao).
# --------------------------------------------------------------------------- #
_recipient_session: X25519PrivateKey | None = None
# True se, no ultimo unlock, a `recipient.pub` em disco DIVERGIA da chave real — sinal de
# adulteracao da publica em claro (ver "vetor da pub" em docs/SECURITY.md). A UI avisa.
_recipient_pub_divergent: bool = False


class RecipientLocked(Exception):
    """A chave de destinatario esta protegida por senha; destrave (unlock_recipient) para abrir."""


class RecipientClearCopyRemains(Exception):
    """A protecao FOI concluida (cofre gravado e verificado), mas a copia EM CLARO nao pudo ser
    removida e continua no disco. Nao e falha de protecao — e um aviso que precisa de acao: e por
    isso que nao herda de VaultError (a UI nao deve dizer "nao foi possivel proteger")."""


def _recipient_path() -> str:
    return os.path.join(_data_dir(), "recipient.x25519")    # privada X25519 (raw 32 bytes, local)


def _recipient_vault_path() -> str:
    return os.path.join(_data_dir(), "recipient.rdbt")      # privada PROTEGIDA (cofre)


def _recipient_pub_path() -> str:
    return os.path.join(_data_dir(), "recipient.pub")       # publica em CLARO (b64)


_X_RAW = (serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _x_pub_raw_of(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _write_recipient_pub(pub_b64: str) -> None:
    """Grava a publica em claro ATOMICAMENTE (temp + fsync + replace). Propaga OSError — os
    chamadores decidem se e fatal (proteger) ou best-effort (leitura/unlock)."""
    _atomic_write(_recipient_pub_path(), (pub_b64 + "\n").encode("ascii"))


def recipient_is_protected() -> bool:
    """True se a privada de destinatario esta embrulhada por senha (existe recipient.rdbt)."""
    return os.path.exists(_recipient_vault_path())


def recipient_unlocked() -> bool:
    """True se a privada de destinatario esta acessivel agora (em claro, ou destravada na sessao)."""
    return _recipient_session is not None or not recipient_is_protected()


def _recipient_raw_residues() -> list[str]:
    """Caminhos de copia EM CLARO da privada que podem existir agora: o canonico e o temporario de
    uma escrita atomica interrompida (`.tmp`) — o red-team mostrou que o `.tmp` guarda os 32 bytes
    em claro e passava invisivel ao detector e ao curador."""
    p = _recipient_path()
    return [q for q in (p, p + ".tmp") if os.path.isfile(q)]   # isfile: um DIR homonimo nao e residuo


def _recipient_prior_key_evidence() -> bool:
    """Ja existiu uma chave de destinatario nesta instalacao? Olha um CONJUNTO de evidencias, nao um
    arquivo so: qualquer artefato canonico OU o `.tmp` de uma escrita interrompida, mais a chave viva
    na sessao. Com evidencia unica a tripwire era de mentira — bastava o AV comer o arquivo certo
    para o app cunhar outra identidade em silencio."""
    if _recipient_session is not None:
        return True
    for p in (_recipient_path(), _recipient_vault_path(), _recipient_pub_path()):
        if os.path.isfile(p) or os.path.isfile(p + ".tmp"):
            return True
    return False


def recipient_has_orphan_raw() -> bool:
    """Estado INCONSISTENTE: chave protegida (recipient.rdbt) E uma copia em CLARO
    (recipient.x25519, ou o `.tmp` de uma escrita interrompida) coexistindo. Acontece quando a
    remocao da copia em claro falha (lock de AV/sync) ou o processo morre no meio; isto detecta o
    residuo para a UI AVISAR e para o curador limpar no proximo unlock (espelha
    identity_has_orphan_pem)."""
    return recipient_is_protected() and bool(_recipient_raw_residues())


def recipient_pub_was_divergent() -> bool:
    """True se o ultimo unlock encontrou a `recipient.pub` em disco DIVERGINDO da chave real —
    ou seja, alguem adulterou a publica em claro (e cofres selados nesse periodo podem ter ido
    para OUTRA chave). O unlock re-grava a publica correta; isto existe para a UI avisar."""
    return _recipient_pub_divergent


def recipient_unlockers() -> list[int]:
    """Tipos de destravador da chave de destinatario (0=senha, 1=arquivo-chave). [] se em claro."""
    if not recipient_is_protected():
        return []
    try:
        with open(_recipient_vault_path(), "rb") as fh:
            return vault.slot_kinds(fh.read())
    except OSError:
        return []


def _open_protected_recipient(passphrase: str | None = None, *,
                              keyfile: bytes | None = None) -> X25519PrivateKey:
    """Abre o cofre da chave de destinatario e reconstroi a privada.
    Levanta vault.VaultError (WrongPassword/etc.) em qualquer falha de credencial/conteudo — e
    tambem quando o arquivo esta ilegivel (lock de AV/backup, ACL): OSError NUNCA escapa cru,
    senao derrubaria o slot Qt que chamou."""
    try:
        with open(_recipient_vault_path(), "rb") as fh:
            blob = fh.read()
    except OSError as exc:
        raise vault.VaultError(f"nao consegui ler o cofre da chave de destinatario: {exc}") from exc
    raw_b64 = vault.open_vault(blob, password=passphrase, keyfile=keyfile).text
    try:
        raw = base64.b64decode(raw_b64, validate=True)
        return X25519PrivateKey.from_private_bytes(raw)
    except (binascii.Error, ValueError) as exc:
        raise vault.VaultError("conteudo do cofre da chave de destinatario invalido") from exc


def _load_or_create_recipient() -> X25519PrivateKey:
    """A privada de destinatario. Protegida: usa o cache da sessao, senao RecipientLocked.
    Em claro: carrega (ou gera, na 1a vez). NUNCA regenera por cima de um arquivo existente —
    isso perderia o acesso a cofres ja selados para voce."""
    if _recipient_session is not None:
        return _recipient_session       # chave VIVA na sessao manda: nunca cunhar outra por cima
    if recipient_is_protected():
        raise RecipientLocked("chave de destinatario protegida por senha")
    p = _recipient_path()
    if os.path.exists(p):
        try:
            with open(p, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            raise CustodyError("nao consegui ler a chave de destinatario") from exc
        if len(raw) != 32:
            raise CustodyError("chave de destinatario (recipient.x25519) corrompida")
        try:
            return X25519PrivateKey.from_private_bytes(raw)
        except ValueError as exc:
            raise CustodyError("chave de destinatario (recipient.x25519) invalida") from exc
    # TRIPWIRE (red-team v1.3): existe uma publica em claro mas NENHUMA privada (nem raw, nem
    # cofre) -> a chave foi removida/quarentenada. Gerar outra aqui seria catastrofico e SILENCIOSO:
    # trocaria a sua identidade de destinatario (perdendo o acesso a tudo que ja foi selado pra voce)
    # e ainda publicaria a nova como se fosse a mesma. Erra alto e manda restaurar o backup.
    if _recipient_prior_key_evidence():
        raise CustodyError(
            "chave de destinatario AUSENTE: ha vestigio de uma chave anterior (recipient.pub/.tmp) "
            "mas nem recipient.x25519 nem recipient.rdbt — restaure o backup. Gerar outra trocaria "
            "sua identidade e faria voce perder o acesso aos cofres ja selados para voce")
    key = X25519PrivateKey.generate()
    _atomic_write(p, key.private_bytes(*_X_RAW))
    return key


def _heal_orphan_recipient(key: X25519PrivateKey) -> bool:
    """Remove as copias em CLARO (recipient.x25519 e o `.tmp`) que sobraram coexistindo com o
    cofre — residuo de um proteger interrompido. So apaga o que for a MESMA chave (nunca outra:
    apagar chave alheia seria perda de dados). Devolve True se limpou alguma."""
    if not recipient_is_protected():
        return False
    limpou = False
    for p in _recipient_raw_residues():
        try:
            with open(p, "rb") as fh:
                raw = fh.read()
            if len(raw) != 32:
                # NAO e chave (ex.: residuo zerado de um wipe cujo remove falhou): e lixo nosso no
                # nosso caminho canonico — limpar aqui e o que impede a "pendencia eterna".
                same = True
            else:
                same = _x_pub_raw_of(X25519PrivateKey.from_private_bytes(raw)) == _x_pub_raw_of(key)
        except (OSError, ValueError):
            continue
        if not same:
            continue                            # chave DIFERENTE: conservador, nunca apaga
        try:
            _secure_remove(p)
            limpou = True
        except OSError:
            pass
    return limpou


def _recipient_pub_raw() -> bytes:
    """Publica de destinatario (32 bytes), SEM pedir senha. Protegida e travada: le a pub em
    claro (recipient.pub) — por isso exportar/selar funcionam com a privada trancada."""
    if _recipient_session is not None:
        return _x_pub_raw_of(_recipient_session)
    if not recipient_is_protected():
        raw = _x_pub_raw_of(_load_or_create_recipient())
        try:
            _write_recipient_pub(base64.b64encode(raw).decode())   # sincroniza a pub em claro
        except OSError:
            pass          # best-effort: pub e cache derivado da privada; ler nunca deve falhar por isso
        return raw
    try:
        with open(_recipient_pub_path(), encoding="ascii") as fh:
            raw = base64.b64decode(fh.read().strip(), validate=True)
    except (OSError, binascii.Error, ValueError) as exc:
        raise CustodyError(
            "chave publica de destinatario (recipient.pub) ausente ou ilegivel") from exc
    if len(raw) != 32:
        raise CustodyError("chave publica de destinatario (recipient.pub) com tamanho invalido")
    return raw


def recipient_public_b64() -> str:
    """Sua chave PUBLICA de destinatario (32 bytes, base64) — compartilhe para receberem cofres
    selados para voce. Gera o par na 1a chamada; NAO pede senha se estiver protegida."""
    return base64.b64encode(_recipient_pub_raw()).decode()


def recipient_fingerprint() -> str:
    """Impressao digital curta da chave de destinatario: sha256(pub)[:16]. Sem senha."""
    return hashlib.sha256(_recipient_pub_raw()).hexdigest()[:16]


def recipient_private_bytes(passphrase: str | None = None) -> bytes:
    """Bytes da chave PRIVADA de destinatario (raw, 32 bytes) — para ABRIR cofres selados para
    voce. NAO compartilhe. Protegida: usa o cache da sessao ou a `passphrase`; senao
    RecipientLocked (a UI deve pedir a senha e chamar unlock_recipient)."""
    if recipient_is_protected() and _recipient_session is None and passphrase is not None:
        if not unlock_recipient(passphrase):
            raise vault.WrongPassword("senha da chave de destinatario incorreta")
    return _load_or_create_recipient().private_bytes(*_X_RAW)


def recipient_exists() -> bool:
    """True se ja existe um par de destinatario no disco (em claro OU protegido), sem cria-lo."""
    return os.path.exists(_recipient_path()) or recipient_is_protected()


def unlock_recipient(passphrase: str | None = None, *, keyfile: bytes | None = None) -> bool:
    """Destrava e cacheia a privada de destinatario por esta sessao. False se a credencial estiver
    errada (ou o cofre ilegivel/corrompido — nunca levanta OSError, que derrubaria o slot Qt).
    Ao destravar, DETECTA se a recipient.pub em disco divergia da chave real (adulteracao da
    publica em claro -> recipient_pub_was_divergent()), re-grava a publica correta (binding
    pub <-> chave) e limpa uma copia em claro residual."""
    global _recipient_session, _recipient_pub_divergent
    if not recipient_is_protected():
        return True
    try:
        key = _open_protected_recipient(passphrase, keyfile=keyfile)
    except vault.VaultError:
        return False
    real_b64 = base64.b64encode(_x_pub_raw_of(key)).decode()
    # A SESSAO E SETADA PRIMEIRO: o resto daqui e diagnostico/manutencao opcional. Antes, uma
    # falha ao LER a pub abortava a funcao com a sessao ainda vazia -> voce ficava sem acesso ao
    # seu proprio cofre (e byte nao-ASCII na pub virava UnicodeDecodeError escapando p/ o slot Qt).
    _recipient_session = key
    try:                                        # a pub em disco batia com a chave real?
        with open(_recipient_pub_path(), encoding="ascii") as fh:
            _recipient_pub_divergent = (fh.read().strip() != real_b64)
    except (OSError, UnicodeDecodeError, ValueError):
        _recipient_pub_divergent = False        # ausente/ilegivel nao e adulteracao: re-grava abaixo
    try:
        _write_recipient_pub(real_b64)          # re-amarra a publica a chave real
    except OSError:
        pass                                    # best-effort: nao impede o destravamento
    _heal_orphan_recipient(key)
    return True


def lock_recipient() -> None:
    """Esquece a privada de destinatario cacheada (ex.: no auto-lock do app)."""
    global _recipient_session
    _recipient_session = None


def protect_recipient(passphrase: str | None = None, *, keyfile: bytes | None = None) -> None:
    """Protege a chave de destinatario ATUAL (preserva o fingerprint) embrulhando-a num Cofre e
    removendo a copia em claro. Levanta vault.VaultError se ja protegida ou sem credencial."""
    global _recipient_session
    if recipient_is_protected():
        raise vault.VaultError("chave de destinatario ja esta protegida")
    if not passphrase and not keyfile:
        raise vault.VaultError("forneca uma senha ou um arquivo-chave")
    # Se existe uma publica em claro sem privada, `_load_or_create_recipient` dispara o TRIPWIRE
    # (nao inventa outra chave). Sem consultar a pub aqui, `recipient_exists()` seria False nesse
    # estado e a gente geraria uma chave NOVA em silencio — trocando a sua identidade e matando o
    # acesso ao que ja foi selado pra voce. Instalacao realmente limpa: gera em MEMORIA (a privada
    # nunca toca o disco em claro).
    if _recipient_prior_key_evidence():
        key = _load_or_create_recipient()
    else:
        key = X25519PrivateKey.generate()
    raw = key.private_bytes(*_X_RAW)

    try:
        blob = vault.new_vault(base64.b64encode(raw).decode(),
                               password=passphrase or None, keyfile=keyfile)
        _atomic_write(_recipient_vault_path(), blob)
    except OSError as exc:                         # nao pode escapar cru do slot Qt
        raise vault.VaultError(
            f"nao consegui gravar o cofre da chave de destinatario: {exc}") from exc

    # PROVA que o cofre devolve ESTA chave antes de destruir a copia em claro. Se a prova falhar,
    # desfazer o cofre e seguro: a copia em claro esta intacta, nada se perde.
    try:
        if _x_pub_raw_of(_open_protected_recipient(passphrase, keyfile=keyfile)) != _x_pub_raw_of(key):
            raise vault.VaultError("o cofre da chave de destinatario nao devolveu a mesma chave")
    except BaseException:
        try:
            _force_remove(_recipient_vault_path())  # unico rollback seguro (pre-destruicao)
        except OSError:
            pass
        if os.path.isfile(_recipient_vault_path()):
            raise vault.VaultError(
                "o cofre da chave de destinatario foi gravado mas nao pudo ser verificado NEM "
                "removido — a sua chave em claro continua intacta; feche programas que possam estar "
                "usando o arquivo (antivirus/sync/backup) e tente de novo")
        raise

    # A publica so DEPOIS do cofre verificado, e best-effort: gravada antes, uma falha no cofre
    # deixava uma "pub orfa" que travava a tripwire e brickava a instalacao limpa. Ela e derivada da
    # privada, entao o proximo destravamento a reconstroi.
    try:
        _write_recipient_pub(base64.b64encode(_x_pub_raw_of(key)).decode())
    except OSError:
        pass

    # Com o cofre PROVADO, remover a copia em claro nao pode mais perder a chave. E se a remocao
    # falhar (lock de AV/sync), NAO desfazemos o cofre: depois do wipe ele e a unica copia boa, e
    # apaga-lo destruiria a chave (foi a regressao que o meu proprio rollback anterior criou).
    # Erramos ALTO — o estado fica detectavel (recipient_has_orphan_raw) e o proximo unlock cura.
    _recipient_session = key                       # protecao confirmada: o cofre abre
    for residuo in _recipient_raw_residues():
        try:
            _secure_remove(residuo)
        except OSError:
            pass
    if _recipient_raw_residues():
        raise RecipientClearCopyRemains(
            "a chave FOI protegida (o cofre esta gravado e verificado), MAS nao foi possivel "
            "remover a copia EM CLARO (recipient.x25519) — ela CONTINUA no disco. Feche programas "
            "que possam estar usando o arquivo (antivirus/sync/backup); abrir um cofre selado para "
            "voce (que pede a senha) remove a copia automaticamente")


def unprotect_recipient(passphrase: str | None = None, *, keyfile: bytes | None = None) -> None:
    """Remove a protecao: volta a privada de destinatario para o arquivo raw em claro."""
    global _recipient_session
    if not recipient_is_protected():
        raise vault.VaultError("chave de destinatario nao esta protegida")
    key = _open_protected_recipient(passphrase, keyfile=keyfile)
    try:
        _atomic_write(_recipient_path(), key.private_bytes(*_X_RAW))
    except OSError as exc:                         # nao pode escapar cru do slot Qt
        raise vault.VaultError(
            f"nao consegui gravar a chave de destinatario em claro: {exc}") from exc
    try:
        os.chmod(_recipient_path(), 0o600)         # so o dono le (best-effort no Windows)
    except OSError:
        pass
    # PROVA que a copia em claro le de volta a MESMA chave antes de remover o cofre.
    try:
        with open(_recipient_path(), "rb") as fh:
            de_volta = fh.read()
    except OSError as exc:
        raise vault.VaultError(f"nao consegui verificar a chave em claro: {exc}") from exc
    if de_volta != key.private_bytes(*_X_RAW):
        raise vault.VaultError("a copia em claro nao confere com a chave do cofre")
    # `os.remove` SEM wipe: o cofre e CIFRADO (nao ha plaintext a sobrescrever) e sobrescrever
    # ANTES de conseguir apaga-lo corrompia a unica copia recuperavel — era o caminho de PERDA
    # TOTAL da identidade que o red-team provou (cofre virava lixo e o raw era apagado depois).
    try:
        _force_remove(_recipient_vault_path())     # chmod + remove (o `+R` fazia falhar sempre)
    except OSError:
        pass
    if recipient_is_protected():
        # NAO apagamos a copia em claro aqui (era exatamente a perda total): o cofre segue intacto
        # e utilizavel, e o residuo em claro fica detectavel/curavel no proximo unlock.
        raise vault.VaultError(
            "nao foi possivel remover o cofre da chave de destinatario — a chave SEGUE PROTEGIDA e "
            "uma copia em claro pode ter ficado no disco (o proximo destravamento a remove). Feche "
            "programas que possam estar usando o arquivo (antivirus/sync/backup) e tente de novo")
    try:
        _write_recipient_pub(base64.b64encode(_x_pub_raw_of(key)).decode())
    except OSError:
        pass                                       # best-effort: a pub e derivada da privada
    _recipient_session = key


def add_recipient_unlocker(passphrase: str | None = None, *, keyfile: bytes | None = None,
                           new_password: str | None = None,
                           new_keyfile: bytes | None = None) -> None:
    """Adiciona uma senha/arquivo-chave EXTRA ao cofre da chave de destinatario (rota de backup)."""
    if not recipient_is_protected():
        raise vault.VaultError("chave de destinatario nao esta protegida")
    if not new_password and not new_keyfile:
        raise vault.VaultError("forneca a nova senha ou o novo arquivo-chave")
    try:
        with open(_recipient_vault_path(), "rb") as fh:
            blob = fh.read()
    except OSError as exc:                     # nunca escapa cru do slot Qt
        raise vault.VaultError(f"nao consegui ler o cofre da chave de destinatario: {exc}") from exc
    opened = vault.open_vault(blob, password=passphrase, keyfile=keyfile)
    try:                                       # o cofre guarda MESMO uma chave X25519?
        X25519PrivateKey.from_private_bytes(base64.b64decode(opened.text, validate=True))
    except (binascii.Error, ValueError) as exc:
        raise vault.VaultError("conteudo do cofre da chave de destinatario invalido") from exc
    slots = vault.add_unlocker(opened.key, opened.slots,
                               password=new_password, keyfile=new_keyfile)
    try:
        _atomic_write(_recipient_vault_path(), vault.reseal(opened.text, opened.key, slots))
    except OSError as exc:
        raise vault.VaultError(f"nao consegui gravar o cofre da chave de destinatario: {exc}") from exc


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
    """Sobrescreve o conteudo (best-effort), TRUNCA e remove. Em SSD/COW o overwrite nao garante
    apagamento fisico, mas reduz a janela de recuperacao da chave em claro. Propaga OSError
    do os.remove de proposito — o chamador verifica e trata.

    O `truncate(0)` importa: se o remove falhar DEPOIS do wipe (modo de falha real no Windows —
    lock de AV/sync), o residuo ficaria com bytes ALEATORIOS. E 32 bytes aleatorios sao uma chave
    X25519 VALIDA e DIFERENTE — uma isca que o carregador adotaria em silencio (trocando a sua
    identidade) e que o curador nunca removeria, por parecer "chave de outra pessoa". Zerado, o
    residuo nao e chave nenhuma: o carregador erra alto e o curador limpa."""
    try:
        os.chmod(path, stat.S_IWRITE)   # limpa "somente-leitura" (senao o remove falha no Windows
    except OSError:                     # e a limpeza da copia em claro falharia em silencio)
        pass
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.write(os.urandom(size))
            fh.flush()
            os.fsync(fh.fileno())
            fh.truncate(0)              # residuo deixa de ser uma chave/PEM valido
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    os.remove(path)


def _force_remove(path: str) -> None:
    """Remove SEM sobrescrever (para arquivos CIFRADOS, como os cofres: nao ha plaintext a apagar).
    Limpa o atributo somente-leitura antes — senao o `+R` fazia a remocao falhar sempre."""
    try:
        os.chmod(path, stat.S_IWRITE)
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
    return is_protected() and bool(_pem_residues())


def _pem_residues() -> list[str]:
    """Copias em CLARO da privada Ed25519 que podem existir: o PEM canonico e o `.tmp` de uma
    escrita atomica interrompida (que tambem guarda a chave em claro)."""
    p = _pem_path()
    return [q for q in (p, p + ".tmp") if os.path.isfile(q)]


def _heal_orphan_pem(key: Ed25519PrivateKey) -> bool:
    """Se ha um PEM nu coexistindo com o cofre E ele e a MESMA chave de `key`, remove-o (com wipe),
    eliminando a copia em claro. So apaga apos confirmar que a chave publica bate — NUNCA remove uma
    chave diferente. Devolve True se limpou. Chamado no unlock, quando temos a chave real em maos."""
    if not is_protected():
        return False
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    limpou = False
    for pem in _pem_residues():
        try:
            with open(pem, "rb") as fh:
                dados = fh.read()
            orphan = serialization.load_pem_private_key(dados, password=None)
            same = orphan.public_key().public_bytes(*raw) == key.public_key().public_bytes(*raw)
        except (ValueError, OSError, TypeError):
            # Nao carrega como chave (ex.: residuo zerado de um wipe cujo remove falhou): e lixo
            # nosso no nosso caminho canonico — limpar evita a "pendencia eterna".
            same = os.path.isfile(pem) and os.path.getsize(pem) == 0
        if not same:
            continue                    # chave diferente: nao apaga (conservador)
        try:
            _secure_remove(pem)
            limpou = True
        except OSError:
            pass
    return limpou


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
        key = serialization.load_pem_private_key(fh.read(), password=None)
    # `load_pem_private_key` devolve qualquer tipo de chave. Se o PEM nao for Ed25519 (arquivo
    # trocado/corrompido), erra AQUI com mensagem clara em vez de falhar depois, no `sign`.
    if not isinstance(key, Ed25519PrivateKey):
        raise CustodyError("identity.ed25519 nao contem uma chave Ed25519")
    return key


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


def _local_fingerprint_or_none() -> str | None:
    """Fingerprint da identidade LOCAL se ela JA existir; None caso contrario. Puramente READ-ONLY:
    NAO cria nem grava identidade (diferente de fingerprint(), que materializaria uma chave numa
    instalacao limpa). Usado por check_anchor para nao escrever no disco ao apenas verificar."""
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    if os.path.exists(_pub_path()):
        try:
            with open(_pub_path(), encoding="ascii") as fh:
                pub = base64.b64decode(fh.read().strip(), validate=True)
            return hashlib.sha256(pub).hexdigest()[:16]
        except (OSError, binascii.Error, ValueError):
            return None
    if is_protected():
        return None                              # protegida sem pub em claro: nao da p/ derivar
    if os.path.exists(_pem_path()):
        try:
            with open(_pem_path(), "rb") as fh:
                key = serialization.load_pem_private_key(fh.read(), password=None)
            return hashlib.sha256(key.public_key().public_bytes(*raw)).hexdigest()[:16]
        except (OSError, ValueError, TypeError):
            return None
    return None                                  # sem identidade local — NAO cria


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
    try:
        blob = vault.new_vault(base64.b64encode(raw).decode(),
                               password=passphrase or None, keyfile=keyfile)
        _atomic_write(_vault_path(), blob)     # cofre gravado atomicamente
    except OSError as exc:
        raise vault.VaultError(f"nao consegui gravar o cofre da identidade: {exc}") from exc

    # PROVA que o cofre devolve ESTA identidade antes de destruir o PEM em claro. Se a prova falhar,
    # desfazer o cofre e seguro: o PEM esta intacto. (Sem esta ordem, o caminho real de falha do
    # Windows — wipe OK, remove bloqueado por AV — levava o rollback a apagar o cofre DEPOIS de
    # sobrescrever o PEM: a identidade Ed25519 ficava IRRECUPERAVEL, matando a cadeia de custodia.)
    try:
        if _pub_b64_of(_open_protected(passphrase, keyfile=keyfile)) != _pub_b64_of(key):
            raise vault.VaultError("o cofre da identidade nao devolveu a mesma chave")
    except BaseException:
        try:
            _force_remove(_vault_path())       # unico rollback seguro (pre-destruicao)
        except OSError:
            pass
        if os.path.isfile(_vault_path()):
            raise vault.VaultError(
                "o cofre da identidade foi gravado mas nao pudo ser verificado NEM removido — a sua "
                "chave em claro continua intacta; feche programas que possam estar usando o arquivo "
                "(antivirus/sync/backup) e tente de novo")
        raise

    try:
        _write_pub(_pub_b64_of(key))           # publica em claro (best-effort: e derivada da privada)
    except OSError:
        pass
    _session_key = key                         # protecao confirmada: o cofre abre

    # Com o cofre PROVADO, remover o PEM nao pode mais perder a identidade. Se a remocao falhar,
    # NAO desfazemos o cofre (era a perda total) — erramos alto, e identity_has_orphan_pem() acusa
    # o residuo para a UI avisar e para o proximo unlock curar.
    if os.path.isfile(_pem_path()):
        try:
            _secure_remove(_pem_path())        # sobrescreve, trunca e remove
        except OSError:
            pass
    if os.path.isfile(_pem_path()):            # ainda la? lock de AV/sync/backup
        raise IdentityClearCopyRemains(
            "a identidade FOI protegida (o cofre esta gravado e verificado), MAS nao foi possivel "
            "remover a chave EM CLARO (identity.ed25519) — ela CONTINUA no disco. Feche programas "
            "que possam estar usando o arquivo (antivirus/sync/backup); assinar algo (que pede a "
            "senha) remove a copia automaticamente")


def unprotect_identity(passphrase: str | None = None, *, keyfile: bytes | None = None) -> None:
    """Remove a proteção: volta a privada para PEM sem senha. Levanta WrongPassword se errar."""
    global _session_key
    if not is_protected():
        raise vault.VaultError("identidade nao esta protegida")
    key = _open_protected(passphrase, keyfile=keyfile)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    try:
        _atomic_write(_pem_path(), pem)
    except OSError as exc:
        raise vault.VaultError(f"nao consegui gravar a chave em claro: {exc}") from exc
    try:
        os.chmod(_pem_path(), 0o600)
    except OSError:
        pass
    # PROVA que o PEM le de volta a MESMA identidade antes de remover o cofre.
    try:
        de_volta = _load_legacy()
    except (OSError, ValueError, TypeError) as exc:
        raise vault.VaultError(f"nao consegui verificar a chave em claro: {exc}") from exc
    if de_volta is None or _pub_b64_of(de_volta) != _pub_b64_of(key):
        raise vault.VaultError("a chave em claro nao confere com a identidade do cofre")
    # `_force_remove` (SEM wipe): o cofre e CIFRADO, e sobrescreve-lo ANTES de conseguir apaga-lo
    # corrompia a unica copia recuperavel — com o PEM sendo apagado logo depois, era PERDA TOTAL da
    # identidade. Se o cofre resistir, o PEM fica (a identidade segue protegida e utilizavel).
    try:
        _force_remove(_vault_path())
    except OSError:
        pass
    if os.path.isfile(_vault_path()):
        raise vault.VaultError(
            "nao foi possivel remover o cofre da identidade — ela SEGUE PROTEGIDA e uma copia em "
            "claro pode ter ficado no disco (assinar algo, que pede a senha, a remove). Feche "
            "programas que possam estar usando o arquivo (antivirus/sync/backup) e tente de novo")
    try:
        _write_pub(_pub_b64_of(key))
    except OSError:
        pass
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
    # Campos base + 'seq' QUANDO presente (entradas v2). Entradas legadas (sem seq) sao
    # hasheadas sem ele, preservando a compatibilidade do hash ja gravado. 'sig' NUNCA entra
    # no hash (e calculada SOBRE ele).
    fields = list(_CHAIN_FIELDS)
    if "seq" in entry:
        fields.append("seq")
    payload = json.dumps({k: entry.get(k, "") for k in fields},
                         sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _try_sign(data: str) -> str:
    """Assina `data` SE a chave estiver acessivel sem pedir senha (best-effort); senao ''."""
    try:
        return sign(data)
    except IdentityLocked:
        return ""


def read_audit() -> list[dict]:
    p = _audit_path()
    if not os.path.exists(p):
        return []
    out: list[dict] = []
    # errors="replace": um unico byte nao-UTF8 na trilha (corrupcao/adulteracao) levantava
    # UnicodeDecodeError — que nao e OSError, escapava dos leitores e ABORTAVA o processo no slot Qt
    # (justamente em "Verificar custodia", que exibe os avisos de residuo). A linha corrompida vira
    # JSON invalido e e descartada abaixo, como qualquer outra linha suja.
    with open(p, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):       # descarta linhas que nao sao objeto JSON (robustez)
                out.append(obj)
    return out


def log_event(event: str, detail: str = "", content_hash: str = "",
              ts: str | None = None) -> dict:
    """Anexa um evento a trilha, encadeado no hash do anterior.

    Cada entrada carrega 'seq' (posicao 1-based, DENTRO do hash) e 'sig' (assinatura Ed25519 do
    hash, best-effort: vazia se a identidade estiver protegida e travada). O anti-reset forte e a
    ancora exportavel (export_anchor)."""
    entries = read_audit()
    prev = entries[-1].get("hash", "") if entries else ""
    entry = {
        "ts": ts or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event, "detail": detail, "content_hash": content_hash, "prev": prev,
        "seq": len(entries) + 1,
    }
    h = _entry_hash(entry)
    entry["hash"] = h
    entry["sig"] = _try_sign(h)
    with open(_audit_path(), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def verify_chain() -> tuple[bool, int]:
    """Verifica a integridade da cadeia. Retorna (intacta, indice_da_quebra | -1).

    Valida o encadeamento prev<->hash e, para entradas v2 (com 'seq'), que seq == posicao
    (1-based) — pega remocao/reordenacao no MEIO. NAO detecta reset/truncamento do FIM (a cadeia
    recomecada e internamente valida): para isso, use a ANCORA (export_anchor/check_anchor). Tambem
    NAO valida a 'sig' por-entrada (best-effort/forense) — a prova forte de autoria/anti-reset e a ancora."""
    prev = ""
    for i, e in enumerate(read_audit()):
        if e.get("prev", "") != prev:
            return False, i
        if _entry_hash(e) != e.get("hash"):
            return False, i
        if "seq" in e and e.get("seq") != i + 1:
            return False, i
        prev = e["hash"]
    return True, -1


def audit_stats() -> dict:
    """Resumo da trilha para a UI: total de eventos, quantos estao assinados, e o seq da cabeca."""
    entries = read_audit()
    return {
        "total": len(entries),
        "signed": sum(1 for e in entries if e.get("sig")),
        "head_seq": entries[-1].get("seq", len(entries)) if entries else 0,
    }


# --------------------------------------------------------------------------- #
# Ancora exportavel (anti-reset / anti-truncamento da trilha)
# --------------------------------------------------------------------------- #
ANCHOR_FORMAT = "RDBT-ANCHOR1"


def _anchor_payload(seq: int, head_hash: str, ts: str, fingerprint: str) -> str:
    """String canonica que a assinatura da ancora cobre EXATAMENTE (zero divergencia)."""
    return json.dumps({"format": ANCHOR_FORMAT, "seq": seq, "head_hash": head_hash,
                       "ts": ts, "fingerprint": fingerprint},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def export_anchor(ts: str | None = None) -> dict:
    """ANCORA assinada do estado atual da trilha: (seq, head_hash) atestado pela identidade.
    Guardada FORA da maquina, permite depois detectar reset/truncamento (check_anchor). Pede a
    credencial se a identidade estiver protegida (sob demanda). Levanta CustodyError se vazia."""
    entries = read_audit()
    if not entries:
        raise CustodyError("trilha de auditoria vazia — nada a ancorar")
    head = entries[-1]
    seq = head.get("seq", len(entries))
    head_hash = head.get("hash", "")
    if not (isinstance(head_hash, str) and len(head_hash) == 64):
        raise CustodyError("cabeca da trilha sem hash valido — nao e possivel ancorar")
    when = ts or datetime.now(timezone.utc).isoformat(timespec="seconds")
    fp = fingerprint()
    sig = sign(_anchor_payload(seq, head_hash, when, fp))   # IdentityLocked se protegida+travada
    return {"format": ANCHOR_FORMAT, "seq": seq, "head_hash": head_hash, "ts": when,
            "fingerprint": fp, "public_key": public_key_b64(), "sig": sig}


def check_anchor(anchor: dict, expected_fingerprint: str | None = None) -> dict:
    """Verifica uma ANCORA contra a trilha ATUAL **e contra a identidade esperada**.

    A assinatura sozinha NAO prova autoria: a public_key viaja na ancora, entao um atacante
    re-assina com a propria chave. Por isso a autenticidade exige AMARRAR a chave — o fingerprint
    declarado tem que casar com a chave (derivado) E com `expected_fingerprint` (default: a
    identidade LOCAL; o caso de uso e a propria maquina verificando a propria trilha).

    Retorno: sig_ok, fingerprint (DERIVADO da chave), fingerprint_declared_ok, identity_match,
    present, head_match, chain_ok, ok, detail. `ok` exige TODOS. Nunca levanta por ancora malformada."""
    # dict[str, object]: o retorno mistura bool, str e None de proposito (e um relatorio para a UI).
    result: dict[str, object] = {"sig_ok": False, "fingerprint": None,
                                 "fingerprint_declared_ok": False, "identity_match": False,
                                 "present": False, "head_match": False, "chain_ok": False,
                                 "ok": False, "detail": None}
    try:
        seq = anchor["seq"]
        head_hash = anchor["head_hash"]
        ts = anchor["ts"]
        fp_declared = anchor.get("fingerprint", "")
        pub = anchor["public_key"]
        sig = anchor["sig"]
        if not (isinstance(seq, int) and isinstance(head_hash, str) and isinstance(pub, str)):
            raise ValueError("seq/head_hash/public_key invalido")
        fp_real = hashlib.sha256(base64.b64decode(pub, validate=True)).hexdigest()[:16]
    except (KeyError, TypeError, ValueError, binascii.Error) as e:
        result["detail"] = f"ancora malformada: {e}"
        return result

    result["sig_ok"] = verify(_anchor_payload(seq, head_hash, ts, fp_declared), sig, pub)
    result["fingerprint"] = fp_real
    result["fingerprint_declared_ok"] = (fp_declared == fp_real)
    expected = expected_fingerprint
    if expected is None:                        # default: a IDENTIDADE LOCAL, sem CRIAR uma (read-only)
        expected = _local_fingerprint_or_none()
    result["identity_match"] = (expected is not None and fp_real == expected)

    entries = read_audit()
    match = next((e for e in entries if e.get("seq") == seq), None)
    if match is None and 1 <= seq <= len(entries):
        match = entries[seq - 1]                # fallback p/ trilha legada sem 'seq'
    result["present"] = match is not None
    if match is not None:
        result["head_match"] = (match.get("hash") == head_hash)
    result["chain_ok"] = verify_chain()[0]      # a trilha atual nao pode estar adulterada por dentro

    if not result["sig_ok"]:
        result["detail"] = "assinatura da ancora INVALIDA"
    elif not result["fingerprint_declared_ok"]:
        result["detail"] = "ancora inconsistente: o fingerprint declarado nao corresponde a chave"
    elif not result["identity_match"]:
        result["detail"] = (f"ancora assinada por OUTRA chave ({fp_real}) — NAO e a identidade "
                            f"esperada ({expected}); POSSIVEL FORJA")
    elif not result["present"]:
        result["detail"] = (f"trilha RESETADA/TRUNCADA: nao alcanca o seq {seq} "
                            f"(a trilha atual tem {len(entries)} eventos)")
    elif not result["head_match"]:
        result["detail"] = "trilha DIVERGENTE: o hash no ponto ancorado nao confere (reset/reescrita)"
    elif not result["chain_ok"]:
        result["detail"] = "cadeia da trilha QUEBRADA por dentro (adulteracao de evento)"
    else:
        result["detail"] = (f"trilha CONSISTENTE e AUTENTICA (seq {seq}; "
                            f"+{len(entries) - seq} evento(s) novo(s) desde entao)")
    result["ok"] = bool(result["sig_ok"] and result["fingerprint_declared_ok"]
                        and result["identity_match"] and result["present"]
                        and result["head_match"] and result["chain_ok"])
    return result
