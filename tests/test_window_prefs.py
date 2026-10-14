"""Janela e layout: geometria lembrada entre execucoes, tema que segue o sistema e trilho lateral
recolhivel. (As configuracoes ja vao para um .ini temporario do processo — ver conftest.)"""

from PyQt6.QtCore import QByteArray, QSize, Qt
from PyQt6.QtWidgets import QApplication

from notepy import config, theme
from notepy.mainwindow import MainWindow


# --------------------------------------------------------------------------- #
# Geometria da janela
# --------------------------------------------------------------------------- #
def test_lembra_tamanho_e_posicao(win, qapp):
    win.resize(700, 480)                                    # cabe na tela virtual (800x600)
    win.move(20, 30)
    win._save_window_geometry()
    outra = MainWindow()
    assert outra.size() == QSize(700, 480)
    outra.close()


def test_lembra_que_estava_maximizada(win, qapp):
    win.showMaximized()
    qapp.processEvents()
    win._save_window_geometry()
    outra = MainWindow()
    assert outra.windowState() & Qt.WindowState.WindowMaximized
    outra.close()


def test_geometria_invalida_no_registro_e_ignorada(win):
    config._s().setValue("window/geometry", QByteArray(b"lixo que nao e geometria"))
    outra = MainWindow()                                    # nao quebra: fica o tamanho padrao
    assert outra.size() == QSize(1360, 860)
    config._s().setValue("window/geometry", ["tipo", "trocado"])
    assert config.load_window() is None
    outra.close()


def test_tem_tamanho_minimo(win):
    assert win.minimumSize() == QSize(600, 400)


# --------------------------------------------------------------------------- #
# Tema: segue o sistema, com escolha manual salva
# --------------------------------------------------------------------------- #
def _reset_theme():
    config.set_("theme", "system")
    theme.set_theme("dark")


def test_padrao_segue_o_sistema(win, monkeypatch):
    monkeypatch.setattr(theme, "system_scheme", lambda: "light")
    try:
        assert config.get("theme") == "system"
        win.apply_theme()
        assert theme.theme_choice() == "system" and theme.current_theme() == "light"
        assert win._theme_actions["system"].isChecked()
    finally:
        _reset_theme()


def test_sistema_troca_de_modo_com_o_app_aberto(win, monkeypatch):
    modo = ["dark"]
    monkeypatch.setattr(theme, "system_scheme", lambda: modo[0])
    try:
        win.apply_theme()
        assert theme.current_theme() == "dark"
        modo[0] = "light"
        win._on_system_scheme()                       # o que o sinal colorSchemeChanged chama
        assert theme.current_theme() == "light"
        # escolha manual: a mudanca do sistema nao mexe mais
        win.set_theme_choice("dark")
        modo[0] = "light"
        win._on_system_scheme()
        assert theme.current_theme() == "dark"
    finally:
        _reset_theme()


def test_escolha_manual_fica_salva(win, monkeypatch):
    monkeypatch.setattr(theme, "system_scheme", lambda: "dark")
    try:
        win._theme_actions["light"].trigger()         # Exibir ▸ Tema: claro
        assert config.get("theme") == "light" and theme.current_theme() == "light"
        win.toggle_theme()                            # alterna a partir do que esta na tela
        assert config.get("theme") == "dark" and theme.current_theme() == "dark"
        outra = MainWindow()
        assert outra._theme_actions["dark"].isChecked()
        outra.close()
    finally:
        _reset_theme()


def test_tema_invalido_vira_escuro():
    theme.set_theme("sistema-roxo")
    assert theme.theme_choice() == "dark" and theme.current_theme() == "dark"
    assert theme.system_scheme() in ("dark", "light")


def test_preferencias_tem_o_cartao_sistema(win):
    from notepy.preferences import PreferencesDialog
    try:
        config.set_("theme", "dark")
        dlg = PreferencesDialog(win)
        keys = [c.key for c in dlg._cards.buttons()]
        assert keys == ["system", "dark", "light"]
        dlg._pick_theme("system")
        dlg.save()
        assert config.get("theme") == "system"
        dlg.deleteLater()
    finally:
        _reset_theme()


def test_cartao_de_tema_desenha_com_foco(win, qapp):
    from notepy.preferences import ThemeCard
    for key in ("system", "dark"):
        c = ThemeCard(key, "T", "sub")
        c.resize(220, 150)
        c.setFocus()
        assert not c.grab().isNull()                  # paintEvent com foco e 'system' nao quebra


# --------------------------------------------------------------------------- #
# Trilho lateral e painel da Sentinela: recolhiveis, e lembram
# --------------------------------------------------------------------------- #
def test_painel_da_sentinela_alterna_e_lembra(win):
    try:
        assert win.sentinel.isVisibleTo(win) and win.act_toggle_sentinel.isChecked()
        win.act_toggle_sentinel.trigger()             # Ctrl+B / Exibir ▸ Painel da Sentinela
        assert win.sentinel.isHidden() and not win.rail.buttons["sentinela"].isChecked()
        assert config.get("sentinel_open") is False
        outra = MainWindow()
        assert outra.sentinel.isHidden() and not outra.act_toggle_sentinel.isChecked()
        outra._on_rail("sentinela")                   # o botao do trilho tambem salva
        assert not outra.sentinel.isHidden() and config.get("sentinel_open") is True
        outra.close()
    finally:
        config.set_("sentinel_open", True)


def test_trilho_recolhe_e_lembra(win):
    try:
        win.act_toggle_rail.trigger()
        assert win.rail.isHidden() and config.get("rail_visible") is False
        outra = MainWindow()
        assert outra.rail.isHidden() and not outra.act_toggle_rail.isChecked()
        outra.close()
    finally:
        config.set_("rail_visible", True)


def test_ctrl_b_chega_mesmo_com_o_editor_focado(win, qapp):
    from PyQt6.QtTest import QTest
    try:
        win.show()
        win.activateWindow()
        ed = win.current_editor()
        ed.setFocus()
        qapp.processEvents()
        QTest.keyClick(ed, Qt.Key.Key_B, Qt.KeyboardModifier.ControlModifier)
        assert win.sentinel.isHidden()
        assert ed.text() == ""                        # o Scintilla nao comeu a tecla
    finally:
        config.set_("sentinel_open", True)


def test_f6_leva_ao_painel_e_esc_volta(win, qapp):
    try:
        win.show()
        win.activateWindow()
        qapp.processEvents()                          # o foco so vale com a janela ativa
        win._set_sentinel_open(False)
        ed = win.current_editor()
        ed.setText("k = AKIA3FK7XQ2MNP8RTUVW\n")
        ed._rescan_secrets()
        win._update_chrome()
        win._cycle_focus()                            # F6: abre o painel e foca a lista
        assert not win.sentinel.isHidden()
        assert QApplication.focusWidget() is win.sentinel.list
        assert win.sentinel.list.currentRow() == 0
        win.sentinel.dismissed.emit()                 # Esc dentro do painel
        assert QApplication.focusWidget() is ed
    finally:
        config.set_("sentinel_open", True)


def test_fechar_o_painel_com_foco_nele_devolve_ao_editor(win, qapp):
    try:
        win.show()
        win.activateWindow()
        qapp.processEvents()
        win.sentinel.btn_report.setFocus()
        qapp.processEvents()
        assert QApplication.focusWidget() is win.sentinel.btn_report
        win._set_sentinel_open(False)
        assert QApplication.focusWidget() is win.current_editor()
    finally:
        config.set_("sentinel_open", True)


def test_menu_exibir(win):
    titulos = [a.text().replace("&", "") for a in win._menubar.actions()]
    assert "Exibir" in titulos
    m = next(a.menu() for a in win._menubar.actions() if a.text().replace("&", "") == "Exibir")
    textos = [a.text().replace("&", "") for a in m.actions() if not a.isSeparator()]
    assert textos[:2] == ["Painel da Sentinela", "Trilho lateral"]
    assert "Tema: seguir o sistema" in textos and "Alternar tema claro/escuro" in textos
