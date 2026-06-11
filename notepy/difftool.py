"""Diff entre dois arquivos — unified diff (nucleo puro, sem Qt).

`unified(a, b)` devolve as linhas do diff ja classificadas (add/del/hunk/hdr/ctx),
para a GUI colorir. `read_file` le texto pulando binarios. Usa `difflib` (stdlib).
"""

from __future__ import annotations

import difflib

_ENCODINGS = ("utf-8", "cp1252", "latin-1")


def read_file(path: str) -> str | None:
    """Le um arquivo de texto; None se binario (NUL) ou ilegivel."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    for enc in _ENCODINGS:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def unified(a_text: str, b_text: str, name_a: str = "A", name_b: str = "B",
            context: int = 3) -> list[tuple[str, str]]:
    """Lista de (kind, linha) do unified diff. kind: hdr | hunk | add | del | ctx.
    Vazia quando os textos sao identicos."""
    out: list[tuple[str, str]] = []
    for ln in difflib.unified_diff(a_text.splitlines(), b_text.splitlines(),
                                   name_a, name_b, lineterm="", n=context):
        if ln.startswith(("+++", "---")):
            kind = "hdr"
        elif ln.startswith("@@"):
            kind = "hunk"
        elif ln.startswith("+"):
            kind = "add"
        elif ln.startswith("-"):
            kind = "del"
        else:
            kind = "ctx"
        out.append((kind, ln))
    return out


def stats(diff: list[tuple[str, str]]) -> tuple[int, int]:
    """(linhas adicionadas, linhas removidas) — ignora os cabecalhos +++/---."""
    adds = sum(1 for k, _ in diff if k == "add")
    dels = sum(1 for k, _ in diff if k == "del")
    return adds, dels
