"""Testes do diff (notepy/difftool.py) — puro, sem Qt."""

from notepy import difftool


def test_identicos_sem_diferenca():
    d = difftool.unified("a\nb\nc", "a\nb\nc")
    assert d == []
    assert difftool.stats(d) == (0, 0)


def test_linha_adicionada():
    d = difftool.unified("a\nb", "a\nb\nc")
    kinds = [k for k, _ in d]
    assert "add" in kinds
    assert difftool.stats(d) == (1, 0)


def test_linha_removida():
    d = difftool.unified("a\nb\nc", "a\nc")
    assert difftool.stats(d) == (0, 1)


def test_linha_modificada_e_del_mais_add():
    d = difftool.unified("titulo: antigo\nfim", "titulo: novo\nfim")
    a, r = difftool.stats(d)
    assert a == 1 and r == 1
    texto = "\n".join(ln for _, ln in d)
    assert "-titulo: antigo" in texto and "+titulo: novo" in texto


def test_classifica_hunk_e_cabecalho():
    d = difftool.unified("a\nb\nc", "a\nX\nc", name_a="velho.txt", name_b="novo.txt")
    kinds = {k for k, _ in d}
    assert "hunk" in kinds and "hdr" in kinds and "ctx" in kinds


def test_read_file_pula_binario(tmp_path):
    p = tmp_path / "bin.dat"; p.write_bytes(b"abc\x00def")
    assert difftool.read_file(str(p)) is None
    t = tmp_path / "ok.txt"; t.write_text("linha", encoding="utf-8")
    assert difftool.read_file(str(t)) == "linha"
