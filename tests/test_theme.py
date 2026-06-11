"""Testes da troca de tema (notepy/theme.py) — puro Python, sem Qt rodando."""

from notepy import theme


def test_set_theme_troca_a_paleta():
    try:
        theme.set_theme("light")
        assert theme.current_theme() == "light"
        assert theme.BG == "#FFFFFF"
        assert "#FFFFFF" in theme.QSS          # QSS reconstruido com a paleta clara
        theme.set_theme("dark")
        assert theme.current_theme() == "dark"
        assert theme.BG == "#0E1116"
    finally:
        theme.set_theme("dark")                # nao vaza estado pros outros testes


def test_tema_desconhecido_cai_no_dark():
    try:
        theme.set_theme("roxo-neon")
        assert theme.current_theme() == "dark"
    finally:
        theme.set_theme("dark")


def test_semantica_de_cor_preservada_nos_dois_temas():
    # AMBER/GREEN/RED existem e diferem entre si nos dois temas (semantica mantida).
    for t in ("dark", "light"):
        theme.set_theme(t)
        assert len({theme.AMBER, theme.GREEN, theme.RED}) == 3
    theme.set_theme("dark")
