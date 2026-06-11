"""Testes da busca em arquivos (notepy/searchfiles.py) — nucleo puro, sem Qt."""

from notepy import searchfiles


def _mk(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_busca_literal_acha_linha_e_arquivo(tmp_path):
    _mk(tmp_path, "a.txt", "alpha\nbeta token aqui\ngamma")
    _mk(tmp_path, "b.txt", "nada relevante")
    hits = searchfiles.search_in_dir(str(tmp_path), "token")
    assert len(hits) == 1
    assert hits[0].line == 2 and hits[0].col == 6 and "token" in hits[0].text
    assert hits[0].path.endswith("a.txt")


def test_case_insensitive_por_padrao(tmp_path):
    _mk(tmp_path, "a.txt", "Token\ntoken\nTOKEN")
    assert len(searchfiles.search_in_dir(str(tmp_path), "token")) == 3
    assert len(searchfiles.search_in_dir(str(tmp_path), "token", case=True)) == 1


def test_regex(tmp_path):
    _mk(tmp_path, "a.txt", "v1\nv22\nv333")
    hits = searchfiles.search_in_dir(str(tmp_path), r"v\d{2,}", regex=True)
    assert {h.line for h in hits} == {2, 3}


def test_pula_binario(tmp_path):
    (tmp_path / "bin.dat").write_bytes(b"token\x00secreto")
    assert searchfiles.search_in_dir(str(tmp_path), "token") == []


def test_pula_pastas_pesadas(tmp_path):
    _mk(tmp_path, ".git/x.txt", "token aqui")
    _mk(tmp_path, "node_modules/y.txt", "token aqui")
    _mk(tmp_path, "src/z.txt", "token aqui")
    hits = searchfiles.search_in_dir(str(tmp_path), "token")
    assert len(hits) == 1 and hits[0].path.endswith("z.txt")   # so o de src/


def test_max_results(tmp_path):
    _mk(tmp_path, "a.txt", "\n".join("achei x" for _ in range(50)))
    assert len(searchfiles.search_in_dir(str(tmp_path), "achei", max_results=10)) == 10


def test_regex_invalida_nao_crasha(tmp_path):
    _mk(tmp_path, "a.txt", "abc")
    assert searchfiles.search_in_dir(str(tmp_path), "[", regex=True) == []


def test_query_vazia(tmp_path):
    _mk(tmp_path, "a.txt", "abc")
    assert searchfiles.search_in_dir(str(tmp_path), "") == []
