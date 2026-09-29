"""Testes da interface do redesign: painel da Sentinela, faixa de alerta, cartao de cofre
travado, barra de status, barra superior, trilho e dialogos. Rodam na janela real (fixture
`win`), com o Qt offscreen."""

from PyQt6.QtWidgets import QApplication, QLabel, QTabBar

from notepy import custody, widgets

AWS = "AKIA3FK7XQ2MNP8RTUVW"


def _texto_visivel(widget) -> str:
    return " ".join(lbl.text() for lbl in widget.findChildren(QLabel))


def _com_segredo(win, texto=f'k = "{AWS}"\ncpf = "529.982.247-25"\n'):
    ed = win.current_editor()
    ed.setText(texto)
    ed._rescan_secrets()
    win._update_chrome()
    return ed


# --------------------------------------------------------------------------- #
# Painel da Sentinela
# --------------------------------------------------------------------------- #
def test_painel_lista_os_segredos_mascarados_e_navega(win):
    ed = _com_segredo(win)
    lst = win.sentinel.list
    assert lst.count() == 2
    assert AWS not in _texto_visivel(win.sentinel)                 # nunca em claro na tela
    assert "529.982.247-25" not in _texto_visivel(win.sentinel)
    ed.setCursorPosition(0, 0)
    item = next(lst.item(i) for i in range(lst.count())
                if "CPF" in _texto_visivel(lst.itemWidget(lst.item(i))))
    win.sentinel._activate(item)                                    # clique no achado
    assert ed.getCursorPosition()[0] == 1                           # foi para a linha do CPF


def test_filtros_do_painel(win):
    _com_segredo(win)
    p = win.sentinel
    assert p.chips["credencial"].text().endswith("1") and p.chips["pii"].text().endswith("1")
    p._set_filter("pii")
    assert p.list.count() == 1
    p._set_filter("todos")
    assert p.list.count() == 2


def test_painel_com_redacao_nao_mostra_nem_o_prefixo(win):
    _com_segredo(win)
    win._set_redaction(True)
    assert "AKIA" not in _texto_visivel(win.sentinel)
    assert not win.sentinel.btn_redact.isEnabled()                  # ja tarjado


def test_painel_vazio_em_arquivo_limpo(win):
    _com_segredo(win, "texto limpo")
    assert win.sentinel.list.count() == 0
    assert not win.sentinel.empty.isHidden()


# --------------------------------------------------------------------------- #
# Faixa de alerta no editor
# --------------------------------------------------------------------------- #
def test_faixa_exposto_depois_redigido(win):
    ed = _com_segredo(win)
    banner = ed._chrome.banner
    assert not banner.isHidden() and banner.level == "danger"
    win.top_bar.redact.click()                                      # botao "Tarjar" da barra
    assert ed.is_redacted() and win.act_redact.isChecked()
    assert banner.level == "warn"
    win.top_bar.redact.click()
    assert not ed.is_redacted()
    assert banner.level == "danger"


def test_faixa_some_em_arquivo_limpo(win):
    ed = _com_segredo(win)
    ed.setText("nada aqui")
    ed._rescan_secrets()
    win._update_chrome()
    assert ed._chrome.banner.isHidden()


# --------------------------------------------------------------------------- #
# Cofre travado: destravar pelo cartao
# --------------------------------------------------------------------------- #
def test_cartao_do_cofre_travado_destrava_com_a_senha(win):
    ed = win.current_editor()
    ed.setText("conteudo secreto")
    win._inbox += [("pw1234", True), ("pw1234", True)]
    assert win.seal_current()
    win.lock_current()
    ov = ed._chrome.overlay
    assert ed.is_locked() and not ov.isHidden()
    assert "senha" in _texto_visivel(ov)                            # "1 senha" nos destravadores
    ov.password.setText("errada")
    ov.btn_unlock.click()
    assert ed.is_locked() and not ov.error.isHidden()               # erro, continua travado
    ov.password.setText("pw1234")
    ov.btn_unlock.click()
    assert not ed.is_locked() and ov.isHidden()
    assert "conteudo secreto" in ed.text()


# --------------------------------------------------------------------------- #
# Barra de status, barra superior, abas, trilho
# --------------------------------------------------------------------------- #
def test_mensagem_da_barra_de_status_nao_esconde_o_selo(win):
    sb = win.statusBar()
    sb.showMessage("Cofre destravado.", 3000)
    assert sb.currentMessage() == "Cofre destravado."
    assert not win.lbl_seal.isHidden() and not win.lbl_pos.isHidden()
    sb.clearMessage()
    assert sb.currentMessage() == ""


def test_todos_os_menus_cabem_na_barra_superior(win):
    win.top_bar.resize(1440, 40)
    bar = win.top_bar._menubar
    titulos = [a.text().replace("&", "") for a in bar.actions()]
    assert titulos == ["Arquivo", "Editar", "Linguagem", "Segurança", "Ajuda"]
    assert bar.width() >= bar.sizeHint().width()                    # nunca vira ">>"


def test_botao_de_fechar_aba(win):
    win.new_file()
    n = win.tabs.count()
    btn = win.tabs.tabBar().tabButton(n - 1, QTabBar.ButtonPosition.RightSide)
    assert btn is not None and btn.objectName() == "TabClose"
    btn.click()
    assert win.tabs.count() == n - 1


def test_trilho_alterna_o_painel_da_sentinela(win):
    assert not win.sentinel.isHidden()
    win._on_rail("sentinela")
    assert win.sentinel.isHidden() and not win.rail.buttons["sentinela"].isChecked()
    win._on_rail("sentinela")
    assert not win.sentinel.isHidden() and win.rail.buttons["sentinela"].isChecked()


def test_badge_do_trilho_conta_os_segredos(win):
    _com_segredo(win)
    assert win.rail.buttons["sentinela"].badge == 2


def test_copia_mascarada_mostra_o_aviso_sem_o_segredo(win):
    # Segredo exclusivo deste teste: janelas de testes anteriores seguem ligadas ao clipboard e,
    # com o AWS comum em Redacao, mascarariam antes (no app real ha uma janela so).
    chave = "AKIAQWERTYUIOPASDFGH"
    _com_segredo(win, f'k = "{chave}"')
    win._set_redaction(True)
    QApplication.clipboard().setText(chave)
    win._sanitize_clipboard()
    assert not win.toast.isHidden()
    assert chave not in _texto_visivel(win.toast)
    assert chave not in QApplication.clipboard().text()


def test_barra_superior_nao_cria_identidade(win):
    """O botao de identidade so LE: abrir o app numa instalacao limpa nao materializa chave."""
    antes = custody._local_fingerprint_or_none()
    win._update_identity_chip()
    win.verify_custody()                                            # dialogo mockado no conftest
    assert custody._local_fingerprint_or_none() == antes


def test_barra_de_comando_aparece_e_some(win):
    assert win.cmd_bar.isHidden()
    win._open_cmd_bar()
    assert not win.cmd_bar.isHidden()
    win.cmd_bar.setText("goto 1")
    win._run_command()
    assert win.cmd_bar.isHidden()


# --------------------------------------------------------------------------- #
# Dialogos
# --------------------------------------------------------------------------- #
def test_dialogo_de_selar_mede_forca_e_confere(win):
    dlg = widgets.SealDialog("financeiro.txt")
    assert not dlg.ok.isEnabled()
    dlg.pw1.setText("correct horse battery staple")
    dlg.pw2.setText("outra")
    assert dlg.ok.isEnabled() and not dlg.mismatch.isHidden()
    assert "Forte" in dlg.meter.label.text() or "Boa" in dlg.meter.label.text()
    dlg.pw2.setText("correct horse battery staple")
    assert dlg.mismatch.isHidden()
    assert dlg.values() == ("correct horse battery staple", "correct horse battery staple")


def test_selar_valida_tamanho_minimo_como_antes(win):
    ed = win.current_editor()
    ed.setText("x")
    win._inbox += [("abc", True), ("abc", True)]                    # curta demais
    assert not win.seal_current()
    assert not ed.is_vault


def test_dialogo_de_custodia_monta(win):
    r = widgets.CustodyReport(
        name="a.txt", sha256="0" * 64, content_state="changed", signature_state="bad",
        signature_file="a.txt.sig", fingerprint="6b38433243e8f7e7", public_key="x",
        identity_protected=False, warnings=["aviso de teste"], chain_ok=False, chain_break_at=3,
        events_total=4, events_signed=1, recent=[("4", "salvou", "a.txt", "28/09 10:00")])
    chamado = []
    dlg = widgets.CustodyDialog(r, {"protect_identity": lambda: chamado.append(1)})
    txt = _texto_visivel(dlg)
    assert "NÃO confere" in txt and "QUEBRADA" in txt and "aviso de teste" in txt
    dlg._run("protect_identity")
    assert chamado == [1]


def test_preferencias_cartao_de_tema(qapp):
    from notepy.preferences import PreferencesDialog
    dlg = PreferencesDialog()
    claro = next(c for c in dlg._cards.buttons() if c.key == "light")
    claro.click()
    assert dlg.cb_theme.currentData() == "light"
