"""Lista de Redacao — segredos LITERAIS do usuario que o Modo Redacao sempre tarja.

Diferente da Sentinela (que DETECTA por padrao/entropia), aqui o usuario DECLARA strings
exatas (suas senhas/credenciais) a esconder. A lista e guardada CIFRADA num Cofre `.rdbt`
(reusa `vault.py`: AES-256-GCM + Argon2id) — nunca em claro no disco. Destravada com senha,
fica em cache na sessao; o casamento e por SUBSTRING LITERAL (sem regex -> sem ReDoS).

Integracao: `find_in(text)` devolve os spans (start, end) de cada ocorrencia; o editor
transforma em `secrets.Match` (snippet = o proprio trecho) e os junta aos detectados —
entao a tarja, o squiggle, o mapa de exposicao, a contagem e ate o mascaramento de
clipboard valem para os segredos da lista, de graca.

Nucleo puro: sem Qt. O caminho do cofre e o `_data_dir()` da custodia (mesma pasta do app).
"""

from __future__ import annotations

import json

from notepy import custody, vault

_VAULT_NAME = "redaction-list.rdbt"
_MAX_ENTRIES = 256
_MAX_LEN = 4096
_MIN_LEN = 4        # segredo de 1-3 chars nao e credencial — e so geraria spans em massa (DoS)
_MAX_SPANS = 4000   # teto de ocorrencias casadas por varredura (espelha o MAX_MATCHES da Sentinela)

# Cache da sessao. _entries None = TRAVADA (nada carregado). _key/_slots permitem re-selar
# (salvar) sem pedir a senha de novo. Tudo so vive em memoria enquanto destravado.
_entries: list[str] | None = None
_key: bytes | None = None
_slots: list[bytes] | None = None


def _path() -> str:
    import os
    return os.path.join(custody._data_dir(), _VAULT_NAME)


def exists() -> bool:
    import os
    return os.path.exists(_path())


def is_unlocked() -> bool:
    return _entries is not None


def lock() -> None:
    """Esquece a lista e o material de chave (ex.: ao bloquear o app / sair)."""
    global _entries, _key, _slots
    _entries = _key = _slots = None


def _decode(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out = []
    for s in data:
        if isinstance(s, str) and _MIN_LEN <= len(s) <= _MAX_LEN and s not in out:
            out.append(s)
        if len(out) >= _MAX_ENTRIES:
            break
    return out


def unlock(password: str | None = None, *, keyfile: bytes | None = None) -> bool:
    """Destrava a lista existente para a sessao. False se a credencial estiver errada
    (ou o cofre corrompido). Use `init_new` quando ainda nao existe lista."""
    global _entries, _key, _slots
    if not exists():
        return False
    try:
        with open(_path(), "rb") as fh:
            blob = fh.read()
        opened = vault.open_vault(blob, password=password, keyfile=keyfile)
    except (OSError, vault.VaultError):
        return False
    _entries = _decode(opened.text)
    _key = opened.key
    _slots = opened.slots
    return True


def init_new(password: str | None = None, *, keyfile: bytes | None = None) -> None:
    """Inicia uma lista NOVA (em memoria) protegida por senha/arquivo-chave. So vai ao
    disco no proximo `save()`. Levanta vault.VaultError se nao houver credencial."""
    global _entries, _key, _slots
    if not password and not keyfile:
        raise vault.VaultError("forneca uma senha ou um arquivo-chave")
    _entries = []
    _key = vault.generate_key()
    _slots = vault.add_unlocker(_key, [], password=password, keyfile=keyfile)


def _require_unlocked() -> None:
    if _entries is None or _key is None or _slots is None:
        raise vault.VaultError("lista de redacao travada")


def entries() -> list[str]:
    """Copia da lista atual (vazia se travada)."""
    return list(_entries) if _entries is not None else []


def add(secret: str) -> bool:
    """Adiciona um segredo literal a lista (em memoria). Devolve False se curto/longo/duplicado/cheio.
    Exige >= _MIN_LEN: um literal de 1-3 chars nao e credencial e geraria spans em massa (DoS)."""
    _require_unlocked()
    if not (_MIN_LEN <= len(secret) <= _MAX_LEN) or secret in _entries or len(_entries) >= _MAX_ENTRIES:
        return False
    _entries.append(secret)
    return True


def remove(secret: str) -> bool:
    _require_unlocked()
    if secret in _entries:
        _entries.remove(secret)
        return True
    return False


def save() -> None:
    """Persiste a lista CIFRADA (re-sela com a chave/slots em cache — nao pede senha de novo)."""
    _require_unlocked()
    blob = vault.reseal(json.dumps(_entries, ensure_ascii=False), _key, _slots)
    custody._atomic_write(_path(), blob)


def find_in(text: str) -> list[tuple[int, int]]:
    """Spans (start, end) de TODAS as ocorrencias literais dos segredos da lista no `text`.
    Vazio se travada. Substring puro (sem regex). Nao sobrepoe a MESMA string consigo."""
    if not _entries:
        return []
    spans: list[tuple[int, int]] = []
    for secret in _entries:
        start = 0
        while True:
            i = text.find(secret, start)
            if i < 0:
                break
            spans.append((i, i + len(secret)))
            start = i + len(secret)
            if len(spans) >= _MAX_SPANS:        # teto anti-DoS: nao devolve lista ilimitada
                return spans
    return spans
