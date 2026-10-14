"""Estados das telas de dados (verificando / nao verificado / oculto / cofre / vazio / erro),
elementos que nao respondiam e rotulos de acessibilidade."""

import os

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMessageBox

from notepy import custody, editor as editor_mod, theme
from notepy.mainwindow import CommandPalette, DiffDialog, SearchDialog
from notepy.widgets import Finding, SentinelPanel

SEGREDO = "k = AKIA3FK7XQ2MNP8RTUVW\n"


def _panel_title(win) -> str:
    return win.sentinel._empty_title.text()


# --------------------------------------------------------------------------- #
# Painel da Sentinela: so diz "limpo" depois de uma varredura completa
# --------------------------------------------------------------------------- #
def test_painel_limpo_so_com_varredura_completa(win):
    ed = win.current_editor()
    ed.setText("nada de mais aqui\n")
    ed._rescan_secrets()
    win._update_chrome()
    assert win.sentinel.state() == "done"
    assert _panel_title(win) == "Nenhum segredo neste arquivo"


def test_painel_nao_verificado(win, monkeypatch):
    monkeypatch.setattr(editor_mod, "_SCAN_CEILING", 10)
    ed = win.current_editor()
    ed.setText("x" * 50)
    ed._rescan_secrets()
    win._update_chrome()
    assert win.sentinel.state() == "skipped"
    assert win.sentinel.empty.isVisibleTo(win.sentinel)
    assert _panel_title(win) == "Não verificado"


def test_painel_verificando_e_depois_o_resultado(win, monkeypatch):
    monkeypatch.setattr(editor_mod, "_SYNC_SCAN_LIMIT", 10)
    ed = win.current_editor()
    ed.setText("y" * 40 + "\n" + SEGREDO)
    # ja na edicao (antes dos 300 ms do debounce) o estado deixa de ser "limpo"
    assert ed.scan_state() == "pending"
    assert "VERIFICANDO" in win.lbl_seal.text()
    ed._rescan_secrets()                          # o que o debounce dispararia: varredura fatiada
    assert win.sentinel.state() == "pending"
    assert _panel_title(win).startswith("Verificando")
    ed.finish_scan_now()
    assert win.sentinel.state() == "done"
    assert win.sentinel.list.count() == 1


def test_painel_aba_oculta(win, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text(SEGREDO, encoding="utf-8")
    win._restore_one(str(f))
    ed = next(w for i in range(win.tabs.count()) if (w := win.tabs.widget(i)).is_gated())
    win.tabs.setCurrentWidget(ed)
    win._update_chrome()
    assert win.sentinel.state() == "hidden"
    assert _panel_title(win) == "Conteúdo oculto"
    assert "1 credencial" in win.sentinel._empty_text.text()


def test_painel_cofre_e_cofre_travado(win):
    ed = win.current_editor()
    ed.setText("conteudo do cofre\n")
    win._inbox += [("pw1234", True), ("pw1234", True)]
    assert win.seal_current()
    win._update_chrome()
    assert win.sentinel.state() == "vault" and _panel_title(win) == "Cofre"
    win.lock_current()
    win._update_chrome()
    assert win.sentinel.state() == "locked" and _panel_title(win) == "Cofre travado"


def test_filtro_sem_achados_explica(win):
    ed = win.current_editor()
    ed.setText(SEGREDO)                           # so credencial, nenhuma PII
    ed._rescan_secrets()
    win._update_chrome()
    win.sentinel._set_filter("pii")
    assert win.sentinel.empty.isVisibleTo(win.sentinel)
    assert _panel_title(win) == "Nenhum dado pessoal (PII)"
    win.sentinel._set_filter("todos")
    assert win.sentinel.list.count() == 1


def test_teto_da_lista_avisa_e_linhas_tem_texto_acessivel(qapp):
    theme.apply_app(qapp)
    p = SentinelPanel()
    fs = [Finding("AWS Access Key", i + 1, i * 10, "AKIA3FK7XQ2MNP8RTUVW") for i in range(3)]
    p.set_findings(fs, False, total=812)
    assert p.note.isVisibleTo(p) and "Mostrando 3 de 812" in p.note.text()
    txt = p.list.item(0).data(Qt.ItemDataRole.AccessibleTextRole)
    assert "linha 1" in txt and "AKIA" not in txt  # o leitor de tela nunca le o segredo


def test_relatorio_respeita_o_estado(win, monkeypatch):
    vistos = []
    monkeypatch.setattr(QMessageBox, "information",
                        staticmethod(lambda _p, title, text, *a, **k: vistos.append((title, text))))
    monkeypatch.setattr(editor_mod, "_SCAN_CEILING", 10)
    ed = win.current_editor()
    ed.setText("x" * 50)
    ed._rescan_secrets()
    win.show_secret_report()
    title, text = vistos[-1]
    assert "Relatorio" in title and "Não verificado" in text and "LIMPO" not in text


# --------------------------------------------------------------------------- #
# Elementos que nao respondiam
# --------------------------------------------------------------------------- #
def test_paleta_sem_entradas_mortas(win):
    labels = [lbl for lbl, _sc, _fn in win.palette_commands()]
    for titulo in ("Arquivo", "Editar", "Exibir", "Segurança", "Codificar / Decodificar"):
        assert titulo not in labels                # titulos de menu so fechavam a paleta
    if not custody.is_protected():
        assert "Identidade: trocar senha…" not in labels   # desligada no estado atual
    if os.name != "nt":
        assert not any("DPAPI" in lbl for lbl in labels)
    assert "Ir para o painel da Sentinela" in labels
    assert "Painel da Sentinela" in labels and "Tema: seguir o sistema" in labels


def test_paleta_sem_resultado_nao_fecha(qapp):
    chamados = []
    dlg = CommandPalette([("Abrir", "Ctrl+O", lambda: chamados.append(1))])
    dlg._refilter("zzzzzz")
    assert dlg.list.count() == 1 and "Nenhum comando" in dlg.list.item(0).text()
    dlg._run_current()
    assert not chamados and dlg.result() == 0
    dlg._refilter("")
    item = dlg.list.item(0)
    assert item.data(Qt.ItemDataRole.AccessibleTextRole) == "Abrir, atalho Ctrl+O"
    dlg.deleteLater()


def test_selar_aba_oculta_pelo_atalho_revela_antes(win, tmp_path):
    """Ctrl+Shift+L / barra de titulo numa aba OCULTA cifrava o texto de aviso."""
    f = tmp_path / "c.txt"
    f.write_text(SEGREDO, encoding="utf-8")
    win._restore_one(str(f))
    ed = next(w for i in range(win.tabs.count()) if (w := win.tabs.widget(i)).is_gated())
    win.tabs.setCurrentWidget(ed)
    win._inbox += [("pw1234", True), ("pw1234", True)]
    assert win.seal_current()
    assert ed.is_vault and not ed.is_gated()
    assert "AKIA3FK7XQ2MNP8RTUVW" in ed.text()     # o cofre guarda o conteudo, nao o aviso
    assert "OCULTO" not in ed.text()


def test_busca_linha_do_arquivo_abre_na_primeira_ocorrencia(qapp, tmp_path):
    (tmp_path / "a.txt").write_text("um\nalvo aqui\nalvo de novo\n", encoding="utf-8")
    abertos = []
    dlg = SearchDialog(lambda path, line: abertos.append((path, line)), str(tmp_path))
    dlg.q.setText("alvo")
    assert dlg.run_search() == 2
    dlg._activate(dlg.tree.topLevelItem(0))
    assert abertos == [(str(tmp_path / "a.txt"), 2)]
    dlg.deleteLater()


def test_busca_estados(qapp, tmp_path):
    (tmp_path / "a.txt").write_text("conteudo\n", encoding="utf-8")
    dlg = SearchDialog(lambda *_: None, str(tmp_path))
    dlg.q.setText("")
    dlg.run_search()
    assert "Digite o texto" in dlg.status.text()
    dlg.q.setText("(sem fechar")
    dlg.cb_regex.setChecked(True)
    dlg.run_search()
    assert "inválida" in dlg.status.text()        # antes: "0 resultado(s)", como se nada houvesse
    dlg.cb_regex.setChecked(False)
    dlg.q.setText("inexistente-xyz")
    assert dlg.run_search() == 0 and "Nada encontrado" in dlg.status.text()
    dlg.folder.setText(str(tmp_path / "nao-existe"))
    dlg.run_search()
    assert "Pasta inexistente" in dlg.status.text()
    dlg.deleteLater()


def test_diff_diz_qual_arquivo_falhou(qapp, tmp_path):
    a = tmp_path / "a.txt"
    a.write_text("x\n", encoding="utf-8")
    dlg = DiffDialog(str(a))
    assert dlg.compare() == -1 and dlg.status.text() == "Escolha o arquivo B."
    dlg.b.setText(str(tmp_path / "sumiu.txt"))
    assert dlg.compare() == -1 and "arquivo B" in dlg.status.text()
    dlg.deleteLater()


def test_cartao_do_cofre_senha_vazia_e_ocupado(win):
    ov = win.current_editor()._chrome.overlay
    ov.password.clear()
    ov._submit()
    assert not ov.error.isHidden() and "Digite a senha" in ov.error.text()
    ov.set_busy(True)
    assert not ov.btn_unlock.isEnabled() and ov.btn_unlock.text() == "Destravando…"
    ov.set_busy(False)
    assert ov.btn_unlock.isEnabled() and ov.btn_unlock.text() == "Destravar"


def test_botao_da_barra_destrava_cofre_selado_para_voce(win, monkeypatch):
    ed = win.current_editor()
    ed.setText("x\n")
    win._inbox += [("pw1234", True), ("pw1234", True)]
    win.seal_current()
    win.lock_current()
    ov = ed._chrome.overlay
    ov.set_info("cofre", "", "RDBT4", "1 destinatário", recipient=True)
    assert not ov.btn_recipient.isHidden()
    chamou = []
    monkeypatch.setattr(win, "unlock_current", lambda: chamou.append(1))
    win._on_seal_button()                          # antes: so focava o campo de senha
    assert chamou == [1]
    ov.recipient_requested.emit()                  # o botao do proprio cartao tambem
    assert chamou == [1, 1]


def test_findbar_avisa_regex_invalida_e_somente_leitura(win):
    fb = win.find_bar
    ed = win.current_editor()
    ed.setText("abc\n")
    fb.open_find(True)
    fb.cb_regex.setChecked(True)
    fb.find_edit.setText("(abc")
    fb.find_next()
    assert fb.status.text() == "expressão regular inválida"
    fb.cb_regex.setChecked(False)
    fb.find_edit.setText("abc")
    ed.setReadOnly(True)
    fb.replace_all()
    assert "somente leitura" in fb.status.text()
    ed.setReadOnly(False)


def test_trilha_ilegivel_nao_some_nem_derruba(win, monkeypatch):
    def boom():
        raise OSError("sem permissao")
    monkeypatch.setattr(custody, "verify_chain", boom)
    win._update_chain_label()
    assert "ilegível" in win.lbl_chain.text()
    win.verify_custody()                           # antes: OSError escapava do slot


# --------------------------------------------------------------------------- #
# Acessibilidade e foco
# --------------------------------------------------------------------------- #
def test_contador_do_trilho_vai_para_o_leitor_de_tela(win):
    b = win.rail.buttons["sentinela"]
    win.rail.set_badge(3)
    assert "3 achado" in b.accessibleName()
    win.rail.set_badge(0)
    assert "achado" not in b.accessibleName()


@pytest.mark.parametrize("attr, nome", [("find_edit", "Localizar"), ("cb_case", "Diferenciar"),
                                        ("cb_regex", "Expressão regular")])
def test_findbar_tem_nomes_acessiveis(win, attr, nome):
    assert getattr(win.find_bar, attr).accessibleName().startswith(nome)


def test_foco_visivel_no_estilo():
    for regra in ("QPushButton:focus", "QToolButton#RailButton:focus", "QToolButton#TabClose:focus",
                  "QListWidget#Findings::item:focus", "QCheckBox:focus"):
        assert regra in theme.QSS


def test_preferencias_rotulos_ligados_aos_campos(win):
    from notepy.preferences import PreferencesDialog
    dlg = PreferencesDialog(win)
    assert dlg.sp_size.accessibleName() == "Tamanho da fonte"
    assert dlg.sp_lock.accessibleName() == "Auto-lock do cofre"
    dlg.deleteLater()
