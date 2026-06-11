"""Busca fuzzy da paleta de comandos (nucleo puro, sem Qt).

`fuzzy_score(query, text)` casa as letras da query como SUBSEQUENCIA do texto
(insensivel a maiusculas), pontuando casamentos contiguos e em inicio de palavra.
`rank(query, texts)` devolve os indices que casam, do melhor para o pior.
"""

from __future__ import annotations

_WORD_SEP = " -_/.\t·…"


def fuzzy_score(query: str, text: str) -> int | None:
    """Pontua o quao bem `query` casa `text` como subsequencia. None = nao casa."""
    if not query:
        return 0
    q, t = query.lower(), text.lower()
    score, ti, last = 0, 0, -2
    for qc in q:
        idx = t.find(qc, ti)
        if idx == -1:
            return None
        score += 10 if idx == last + 1 else 1          # bonus por contiguo
        if idx == 0 or t[idx - 1] in _WORD_SEP:
            score += 5                                  # bonus por inicio de palavra
        ti, last = idx + 1, idx
    return score - len(t) // 50                         # leve preferencia por labels curtos


def rank(query: str, texts: list[str]) -> list[int]:
    """Indices de `texts` que casam a query, ordenados do melhor para o pior."""
    scored = []
    for i, t in enumerate(texts):
        s = fuzzy_score(query, t)
        if s is not None:
            scored.append((s, i))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [i for _, i in scored]
