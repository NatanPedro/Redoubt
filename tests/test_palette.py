"""Testes da busca fuzzy da paleta de comandos (notepy/palette.py) — sem Qt."""

from notepy import palette


def test_subsequencia_casa():
    assert palette.fuzzy_score("slv", "Salvar") is not None
    assert palette.fuzzy_score("abr", "Abrir") is not None
    assert palette.fuzzy_score("scofre", "Selar como cofre") is not None


def test_nao_casa_retorna_none():
    assert palette.fuzzy_score("zzz", "Abrir") is None
    assert palette.fuzzy_score("xk", "Salvar") is None      # 'k' nao existe


def test_query_vazia_casa_tudo():
    assert palette.fuzzy_score("", "qualquer") == 0


def test_inicio_de_palavra_pontua_mais():
    # "sc" como inicios de palavra ("Selar como") vale mais que no meio de uma palavra
    inicio = palette.fuzzy_score("sc", "Selar como cofre")
    meio = palette.fuzzy_score("sc", "Buscando")            # s,c contiguos no meio
    assert inicio is not None and meio is not None and inicio > meio


def test_rank_filtra_e_ordena():
    textos = ["Salvar", "Abrir", "Selar como cofre", "Substituir"]
    idx = palette.rank("sl", textos)
    assert 1 not in idx                                     # "Abrir" nao casa 'sl'
    assert 0 in idx                                         # "Salvar" casa
    # o melhor casamento de "sl" vem primeiro (contiguo em "Salvar"/"Selar")
    assert idx[0] in (0, 2)


def test_rank_vazio_quando_nada_casa():
    assert palette.rank("xyzw", ["Abrir", "Salvar"]) == []
