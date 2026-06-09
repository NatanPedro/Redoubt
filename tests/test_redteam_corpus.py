"""Caracterizacao contra o corpus adversarial de red-team (80 casos).

Nao trava em cada caso individual (os rotulos tem ambiguidade), mas exige que
recall e precisao fiquem ACIMA de pisos — pega regressao grande (ex.: se o
scanner voltasse aos ~46%/55% da v1, isto falha alto).
"""

import json
import os

import pytest

from notepy import secrets as s

_CORPUS = os.path.join(os.path.dirname(__file__), "fixtures", "redteam_corpus.json")


def _load():
    with open(_CORPUS, encoding="utf-8") as fh:
        return json.load(fh)


def test_corpus_existe():
    cases = _load()
    assert len(cases) >= 50, "corpus de red-team parece incompleto"


def test_recall_e_precisao_acima_do_piso():
    cases = _load()
    tp = fn = fp = tn = 0
    for c in cases:
        detected = bool(s.scan(c["text"]))
        if c["shouldDetect"]:
            tp, fn = (tp + 1, fn) if detected else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if detected else (fp, tn + 1)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    msg = f"recall={recall:.0%} precision={precision:.0%} (TP={tp} FN={fn} FP={fp} TN={tn})"
    assert recall >= 0.85, "recall caiu demais — " + msg
    assert precision >= 0.78, "precisao caiu demais — " + msg
