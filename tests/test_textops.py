"""Testes das operacoes de linha (textops.py) — Python puro, sem Qt."""

from notepy import textops as TO


def test_sort_asc_desc():
    t = "banana\nApple\ncherry\n"
    assert TO.sort_asc(t) == "Apple\nbanana\ncherry\n"     # maiuscula vem antes (ASCII)
    assert TO.sort_desc(t) == "cherry\nbanana\nApple\n"


def test_sort_ci():
    assert TO.sort_ci("banana\nApple\ncherry\n") == "Apple\nbanana\ncherry\n"


def test_remove_duplicates_preserva_ordem():
    assert TO.remove_duplicates("a\nb\na\nc\nb\n") == "a\nb\nc\n"


def test_remove_blank_lines():
    assert TO.remove_blank_lines("a\n\n  \nb\n") == "a\nb\n"


def test_trim_trailing():
    assert TO.trim_trailing("a  \nb\t\nc") == "a\nb\nc"


def test_case():
    assert TO.to_upper("Olá café") == "OLÁ CAFÉ"
    assert TO.to_lower("Olá CAFÉ") == "olá café"


def test_preserva_quebra_final():
    assert TO.sort_asc("b\na\n").endswith("\n")
    assert not TO.sort_asc("b\na").endswith("\n")


def test_vazio_nao_quebra():
    for fn in (TO.sort_asc, TO.sort_desc, TO.sort_ci, TO.remove_duplicates,
               TO.remove_blank_lines, TO.trim_trailing, TO.to_upper, TO.to_lower):
        assert fn("") == ""
