"""Testes da barra Localizar/Substituir (notepy/findbar.py) — headless."""


def test_find_next_seleciona(win):
    ed = win.current_editor()
    ed.setText("alpha beta alpha gamma")
    fb = win.find_bar
    fb.find_edit.setText("alpha")
    fb.find_next()
    assert ed.selectedText() == "alpha"
    fb.find_next()                      # avanca para a 2a ocorrencia
    assert ed.selectedText() == "alpha"


def test_find_nao_encontra(win):
    ed = win.current_editor()
    ed.setText("abc def")
    fb = win.find_bar
    fb.find_edit.setText("xyz")
    fb.find_next()
    assert ed.selectedText() == ""
    assert "sem ocorrencias" in fb.status.text()


def test_case_sensitive(win):
    ed = win.current_editor()
    ed.setText("Alpha alpha")
    fb = win.find_bar
    fb.cb_case.setChecked(True)
    fb.find_edit.setText("alpha")
    fb.find_next()
    assert ed.selectedText() == "alpha"     # nao casa o "Alpha"


def test_regex(win):
    ed = win.current_editor()
    ed.setText("bar bor baz")
    fb = win.find_bar
    fb.cb_regex.setChecked(True)
    fb.find_edit.setText("b.r")
    fb.find_next()
    assert ed.selectedText() == "bar"


def test_replace_all(win):
    ed = win.current_editor()
    ed.setText("foo bar foo baz foo")
    fb = win.find_bar
    fb.find_edit.setText("foo")
    fb.replace_edit.setText("X")
    assert fb.replace_all() == 3
    assert ed.text() == "X bar X baz X"


def test_replace_one(win):
    ed = win.current_editor()
    ed.setText("cat cat")
    fb = win.find_bar
    fb.find_edit.setText("cat")
    fb.replace_edit.setText("dog")
    fb.replace_one()        # seleciona a 1a
    fb.replace_one()        # substitui e vai para a proxima
    assert "dog" in ed.text()


def test_replace_all_regex_largura_zero_nao_trava(win):
    # REGRESSAO (pentest v0.6): "a*" produz matches de LARGURA ZERO; o loop
    # original (findFirst/replace/findNext) nunca avançava -> congelava a GUI.
    ed = win.current_editor()
    ed.setText("aaa bbb aaa")
    fb = win.find_bar
    fb.cb_regex.setChecked(True)
    fb.find_edit.setText("a*")
    fb.replace_edit.setText("X")
    n = fb.replace_all()                 # tem que RETORNAR (sem loop infinito)
    assert n < 500_000                   # respeitou o backstop _REPLACE_CAP
    assert "aaa" not in ed.text()        # os runs reais de 'a' foram trocados


def test_replace_all_ancora_nao_trava(win):
    # "^" casa largura zero no inicio de cada linha -> tambem nao pode travar.
    ed = win.current_editor()
    ed.setText("l1\nl2\nl3")
    fb = win.find_bar
    fb.cb_regex.setChecked(True)
    fb.find_edit.setText("^")
    fb.replace_edit.setText("> ")
    fb.replace_all()                     # so precisa RETORNAR, sem hang
