"""Operacoes de linha/texto — nucleo puro, sem Qt (estilo Notepad++ Line Operations).

Cada funcao publica e `str -> str` e opera sobre o texto inteiro recebido (a
selecao ou o documento). As operacoes de LINHA normalizam a quebra para `\\n`
no trecho afetado (o editor reaplica o EOL do arquivo ao salvar); a quebra
final do texto e preservada.
"""

from __future__ import annotations


def _join(text: str, lines: list[str]) -> str:
    """Re-junta linhas com `\\n`, preservando a quebra final do texto original."""
    out = "\n".join(lines)
    if text.endswith("\n") and not out.endswith("\n"):
        out += "\n"
    return out


def sort_asc(text: str) -> str:
    return _join(text, sorted(text.splitlines()))


def sort_desc(text: str) -> str:
    return _join(text, sorted(text.splitlines(), reverse=True))


def sort_ci(text: str) -> str:
    """Ordena ignorando maiusculas/minusculas (casefold)."""
    return _join(text, sorted(text.splitlines(), key=str.casefold))


def remove_duplicates(text: str) -> str:
    """Remove linhas duplicadas mantendo a 1a ocorrencia (preserva a ordem)."""
    seen: set[str] = set()
    out: list[str] = []
    for line in text.splitlines():
        if line not in seen:
            seen.add(line)
            out.append(line)
    return _join(text, out)


def remove_blank_lines(text: str) -> str:
    return _join(text, [ln for ln in text.splitlines() if ln.strip()])


def trim_trailing(text: str) -> str:
    """Remove espaco/tab a direita de cada linha (preserva a estrutura de linhas)."""
    return "\n".join(ln.rstrip() for ln in text.split("\n"))


def to_upper(text: str) -> str:
    return text.upper()


def to_lower(text: str) -> str:
    return text.lower()
