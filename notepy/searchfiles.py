"""Busca em arquivos — grep recursivo numa pasta (nucleo puro, sem Qt).

Varre uma pasta, le os arquivos de TEXTO (pula binarios e arquivos grandes) e
devolve os acertos (arquivo, linha, coluna, texto da linha). O dialogo da GUI
(em mainwindow) consome `search_in_dir` e mostra os resultados clicaveis.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# Pastas que normalmente nao interessam (e explodiriam o tempo).
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", ".pytest_cache", ".mypy_cache", ".idea", ".vscode"}
_MAX_FILE = 2_000_000      # nao le arquivo maior que isto (custo)
_MAX_LINE = 10_000         # busca so os primeiros N chars de cada linha (anti-ReDoS)
_ENCODINGS = ("utf-8", "cp1252", "latin-1")


@dataclass
class Hit:
    path: str
    line: int      # 1-based
    col: int       # 1-based
    text: str      # conteudo da linha (truncado)


def _read_text(path: str) -> str | None:
    """Le um arquivo de texto; devolve None se for binario, grande demais ou ilegivel."""
    try:
        if os.path.getsize(path) > _MAX_FILE:
            return None
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\x00" in raw:
        return None                     # binario
    for enc in _ENCODINGS:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def search_in_dir(root: str, query: str, *, regex: bool = False, case: bool = False,
                  max_results: int = 2000) -> list[Hit]:
    """Procura `query` (texto literal ou regex) em todos os arquivos de texto sob `root`.

    Pula pastas pesadas (.git/node_modules/...), binarios e arquivos > 2 MB. Limita o
    total a `max_results`. Cada linha que casa vira UM Hit (coluna = 1o casamento)."""
    if not query:
        return []
    flags = 0 if case else re.IGNORECASE
    try:
        pat = re.compile(query if regex else re.escape(query), flags)
    except re.error:
        return []
    hits: list[Hit] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in sorted(filenames):
            if len(hits) >= max_results:
                return hits
            text = _read_text(os.path.join(dirpath, name))
            if text is None:
                continue
            fpath = os.path.join(dirpath, name)
            for i, line in enumerate(text.splitlines(), start=1):
                m = pat.search(line[:_MAX_LINE])
                if m:
                    hits.append(Hit(fpath, i, m.start() + 1, line.strip()[:500]))
                    if len(hits) >= max_results:
                        return hits
    return hits
