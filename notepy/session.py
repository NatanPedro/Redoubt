"""Integridade da lista de sessao — nucleo puro, sem Qt.

A lista dos arquivos reabertos na proxima inicializacao vive nas CONFIGURACOES (no Windows, o
registro, em HKCU\\Software\\Redoubt\\Redoubt; no Linux, ~/.config/Redoubt/Redoubt.conf), fora
da pasta de dados. Quem conseguia escrever ali escolhia quais arquivos o Redoubt abria sozinho
ao iniciar. Agora a lista vai com um HMAC-SHA256 cuja chave (32 bytes aleatorios) fica na pasta
de dados (arquivo 0600 numa pasta 0700 no Linux), e a lista que nao confere so e reaberta se a
pessoa confirmar, vendo os caminhos.

O que isso fecha: adulteracao por quem escreve nas configuracoes mas NAO le a pasta de dados
(um .reg importado, uma copia ou sincronizacao das configuracoes, uma ferramenta que so mexe no
registro). O que NAO fecha: um programa rodando como voce le a chave e assina o que quiser.
Contra ele continuam valendo os filtros de `restorable` (teto de arquivos, nada de rede, so
caminho absoluto), aplicados a TODA lista, assinada ou nao.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

KEY_FILE = "session.key"
KEY_LEN = 32
MAX_RESTORE = 50                 # teto de arquivos reabertos por sessao (anti-inundacao)
_DOMAIN = "redoubt-session-v1"   # separa este HMAC de qualquer outro uso da mesma chave

# Resultado de `check`
OK = "ok"                        # assinatura confere
LEGACY = "legacy"                # ainda nao ha chave: lista de antes da assinatura (aceita)
EMPTY = "empty"                  # nada a reabrir
TAMPERED = "tampered"            # nao confere, ou nao da para conferir: so com confirmacao


def _payload(paths: list[str], active: int) -> bytes:
    return json.dumps([_DOMAIN, list(paths), int(active)], ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def sign(key: bytes, paths: list[str], active: int) -> str:
    return hmac.new(key, _payload(paths, active), hashlib.sha256).hexdigest()


def check(paths: list[str], active: int, tag: str, key: bytes | None) -> str:
    """Classifica a lista lida das configuracoes.

    Sem chave e sem assinatura e a primeira execucao depois de atualizar: a lista de antes vale
    UMA vez (o proximo fechamento ja a assina). Com a chave presente, lista sem assinatura foi
    escrita por fora — inclusive por uma versao antiga do Redoubt, que nao assina, e por isso a
    decisao fica com a pessoa em vez de ser um "nao" mudo. Assinatura sem chave (pasta de dados
    apagada ou trocada) tambem nao da para conferir."""
    if not paths:
        return EMPTY
    if key is None:
        return LEGACY if not tag else TAMPERED
    if not tag:
        return TAMPERED
    return OK if hmac.compare_digest(sign(key, paths, active), tag) else TAMPERED


# --------------------------------------------------------------------------- #
# Chave (na pasta de dados, junto da identidade)
# --------------------------------------------------------------------------- #
def _key_path() -> str:
    from . import custody
    return os.path.join(custody._data_dir(), KEY_FILE)


def current_key() -> bytes | None:
    """A chave, se existe e tem o tamanho certo; nunca cria."""
    try:
        with open(_key_path(), "rb") as fh:
            data = fh.read(KEY_LEN + 1)
    except OSError:
        return None
    return data if len(data) == KEY_LEN else None


def ensure_key() -> bytes | None:
    """A chave, criada na primeira vez (ou refeita se estiver corrompida). None se a pasta de
    dados nao aceita escrita — a sessao e salva sem assinatura e volta como LEGACY."""
    key = current_key()
    if key is not None:
        return key
    from . import custody
    key = os.urandom(KEY_LEN)
    try:
        custody._atomic_write(_key_path(), key)        # 0600 desde a criacao
    except OSError:
        return None
    return key


# --------------------------------------------------------------------------- #
# Filtros aplicados a QUALQUER lista (assinada ou nao)
# --------------------------------------------------------------------------- #
def is_remote(path: str) -> bool:
    """Caminho de rede — \\\\host\\share, //host/share e as misturas /\\host e \\/host, que o
    Windows aceita igual. O auto-restore nao toca: abrir dispararia timeout de SMB e a
    autenticacao NTLM automatica (entrega do hash da senha a quem controla o host)."""
    return path.replace("\\", "/").startswith("//")


def restorable(paths: list[str]) -> list[str]:
    """Os caminhos que o auto-restore aceita, na ordem: no maximo MAX_RESTORE, so absolutos e
    nenhum de rede. Nao olha o disco (quem chama confere se o arquivo existe)."""
    out: list[str] = []
    for p in paths[:MAX_RESTORE]:
        if isinstance(p, str) and p and not is_remote(p) and os.path.isabs(p):
            out.append(p)
    return out
