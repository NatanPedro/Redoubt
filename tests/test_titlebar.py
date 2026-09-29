"""Barra de titulo unificada: hit-test da moldura (puro), faixas de largura, paleta centrada,
estados dos botoes, impressao digital, botoes de janela, janela inativa e mnemonicos."""

from PyQt6.QtWidgets import QApplication, QStyle

from notepy import theme, titlebar
from notepy import winframe as wf

# --------------------------------------------------------------------------- #
# Hit-test (sem Qt, sem Windows)
# --------------------------------------------------------------------------- #
KW = {"border": 8, "top_border": 4, "caption_height": 40}
MAXB = (1300, 0, 46, 40)
ICON = (10, 11, 18, 18)
MENUS = (36, 0, 300, 40)


def _ht(x, y, maximized=False, w=1440, h=900):
    return wf.hit_test(x, y, w, h, maximized=maximized, max_button=MAXB, sys_icon=ICON,
                       interactive=[MENUS], **KW)


def test_hit_test_bordas_e_cantos():
    assert _ht(1, 1) == wf.HTTOPLEFT
    assert _ht(1438, 1) == wf.HTTOPRIGHT
    assert _ht(1, 898) == wf.HTBOTTOMLEFT
    assert _ht(1438, 898) == wf.HTBOTTOMRIGHT
    assert _ht(700, 1) == wf.HTTOP              # borda de cima vale ATE sobre a barra
    assert _ht(700, 898) == wf.HTBOTTOM
    assert _ht(2, 500) == wf.HTLEFT
    assert _ht(1437, 500) == wf.HTRIGHT


def test_hit_test_barra():
    assert _ht(800, 20) == wf.HTCAPTION         # espaco vazio: arrasto/duplo clique/menu de sistema
    assert _ht(1320, 20) == wf.HTMAXBUTTON      # e o que liga os Snap Layouts do Windows 11
    assert _ht(15, 20) == wf.HTSYSMENU          # icone: menu de sistema
    assert _ht(100, 20) == wf.HTCLIENT          # menus: interativo, fora do arrasto
    assert _ht(800, 300) == wf.HTCLIENT         # corpo


def test_hit_test_maximizada_sem_bordas_de_redimensionar():
    assert _ht(1, 1, maximized=True) != wf.HTTOPLEFT
    assert _ht(700, 1, maximized=True) == wf.HTCAPTION
    assert _ht(1320, 5, maximized=True) == wf.HTMAXBUTTON


# --------------------------------------------------------------------------- #
# Layout puro
# --------------------------------------------------------------------------- #
def test_faixas_de_largura():
    assert titlebar.mode_for(1440) == titlebar.MODE_FULL
    assert titlebar.mode_for(1281) == titlebar.MODE_FULL
    assert titlebar.mode_for(1280) == titlebar.MODE_MID
    assert titlebar.mode_for(960) == titlebar.MODE_MID
    assert titlebar.mode_for(959) == titlebar.MODE_SMALL
    assert titlebar.mode_for(720) == titlebar.MODE_SMALL
    assert titlebar.mode_for(719) == titlebar.MODE_TINY


def test_paleta_centrada_na_janela_nao_no_espaco_livre():
    x, w = titlebar.place_centered(1440, 560, 400, 1100, 320)
    assert w == 560 and x + w // 2 == 720                   # centro da JANELA
    x, w = titlebar.place_centered(1440, 560, 700, 1300, 320)
    assert x == 700 and w == 560                            # colidiria: desliza, sem sobrepor
    x, w = titlebar.place_centered(1000, 560, 400, 700, 320)
    assert w == 0                                           # nao cabe nem no minimo


# --------------------------------------------------------------------------- #
# A barra na janela real
# --------------------------------------------------------------------------- #
def _at(win, width):
    tb = win.top_bar
    tb.resize(width, titlebar.HEIGHT)
    tb._relayout()
    return tb


def test_altura_de_40px(win):
    assert win.top_bar.height() == 40
    for b in (win.top_bar.redact, win.top_bar.seal, win.top_bar.identity, win.top_bar.search):
        assert b.height() == 28


def test_largura_cheia(win):
    tb = _at(win, 1440)
    tb.set_identity("6b38433243e8f7e7", True)
    tb._relayout()
    assert tb.redact.text() == "Tarjar" and tb.seal.text() == "Selar cofre"
    assert tb.identity.text() == "6b38…f7e7"
    assert not tb.search.compact
    assert tb.search.kbd.parent() is tb.search                  # atalho DENTRO do campo
    assert 320 <= tb.search.width() <= 560
    # nunca invade os grupos vizinhos (menus a esquerda, acoes a direita)
    assert tb.search.x() >= tb._menubar.geometry().right() + 1
    assert tb.search.geometry().right() < tb.redact.x()
    # com espaco sobrando, fica no CENTRO DA JANELA (as metricas de fonte do offscreen variam)
    tb = _at(win, 2400)
    assert tb.search.width() == 560
    assert abs(tb.search.x() + tb.search.width() // 2 - 1200) <= 1


def test_paleta_estreita_tira_o_atalho_e_encurta_o_texto(win):
    pill = win.top_bar.search
    pill.fit(2000)                          # folga de sobra (as metricas do offscreen sao largas)
    assert pill.kbd.isVisibleTo(pill) and pill.placeholder.text() == pill.TEXT_LONG
    pill.fit(110)
    assert not pill.kbd.isVisibleTo(pill) and pill.placeholder.text() == pill.TEXT_SHORT
    assert "Ctrl+Shift+P" in pill.toolTip()                     # o atalho continua anunciado


def test_largura_media_so_icones_nas_acoes(win):
    tb = _at(win, 1100)
    assert tb.redact.text() == "" and tb.seal.text() == ""
    assert tb.redact.toolTip() and tb.seal.toolTip()
    assert tb.redact.accessibleName() == "Tarjar"              # leitor de tela continua sabendo


def test_largura_pequena_paleta_240_e_digital_so_icone(win):
    tb = _at(win, 800)
    tb.set_identity("6b38433243e8f7e7", True)
    tb._relayout()
    assert tb.search.width() <= 240 and tb.identity.text() == ""


def test_largura_minima_menus_no_hamburguer(win):
    tb = _at(win, 640)
    assert tb._menubar.isHidden() and not tb.hamburger.isHidden()
    assert tb.search.compact
    tb.rebuild_hamburger()
    assert [a.text() for a in tb._ham_menu.actions()] == [a.text() for a in tb._menubar.actions()]
    _at(win, 1440)
    assert not tb._menubar.isHidden() and tb.hamburger.isHidden()


def test_tarjar_alternavel_com_estado_explicito(win):
    tb = _at(win, 1440)
    tb.redact.click()
    assert tb.redact.isChecked() and tb.redact.accessibleName() == "Redação ligada"
    assert win.current_editor().is_redacted()
    tb.redact.click()
    assert not tb.redact.isChecked() and tb.redact.accessibleName() == "Tarjar"


def test_selar_cofre_tres_rotulos_e_dois_visuais(win):
    tb = _at(win, 1440)
    assert tb.seal.accessibleName() == "Selar cofre" and not tb.seal.property("sealed")
    ed = win.current_editor()
    ed.setText("x")
    win._inbox += [("pw1234", True), ("pw1234", True)]
    tb.seal.click()                                             # sela pela mesma logica de sempre
    assert ed.is_vault and tb.seal.accessibleName() == "Travar cofre" and tb.seal.property("sealed")
    tb.seal.click()                                             # trava
    assert ed.is_locked() and tb.seal.accessibleName() == "Abrir cofre"


def test_digital_copia_e_confirma(win):
    tb = _at(win, 1440)
    tb.set_identity("6b38433243e8f7e7", True)
    assert "6b38433243e8f7e7" in tb.identity.toolTip()         # completa no tooltip
    tb.identity.click()
    assert QApplication.clipboard().text() == "6b38433243e8f7e7"
    assert tb.identity.text() == "Copiado"


def test_botoes_de_janela(win):
    tb = win.top_bar
    assert [b.accessibleName() for b in (tb.btn_min, tb.btn_max, tb.btn_close)] == \
        ["Minimizar", "Maximizar", "Fechar"]
    assert tb.btn_min.size().width() == 46 and tb.btn_min.size().height() == 40
    tb.set_maximized(True)
    assert tb.btn_max.accessibleName() == "Restaurar"
    tb.set_maximized(False)
    tb.btn_close.set_hover(True)
    assert tb.btn_close.colors() == ("#C42B1C", "#FFFFFF")
    tb.btn_min.set_hover(True)
    assert tb.btn_min.colors()[0] == theme.RAISED               # hover neutro do tema


def test_fora_do_windows_moldura_nativa(win):
    """Nos testes (Qt offscreen) nao ha moldura propria: fica a nativa, sem controles duplicados."""
    tb = win.top_bar
    assert tb.native_frame
    assert tb.btn_close.isHidden() and tb.sys_icon.isHidden()
    assert tb.regions()["max_button"] is None


def test_janela_inativa_esmaece_a_barra(win):
    tb = win.top_bar
    tb.set_active(False)
    assert all(abs(e.opacity() - 0.6) < 1e-6 for e in tb._effects)
    tb.set_active(True)
    assert all(e.opacity() == 1.0 for e in tb._effects)


def test_ordem_de_tab_segue_o_visual(win):
    tb = win.top_bar
    seq, w = [], tb.search
    for _ in range(40):
        w = w.nextInFocusChain()
        if w in (tb.redact, tb.seal, tb.identity, tb.btn_min, tb.btn_max, tb.btn_close):
            seq.append(w)
        if len(seq) == 6:
            break
    assert seq == [tb.redact, tb.seal, tb.identity, tb.btn_min, tb.btn_max, tb.btn_close]


def test_mnemonicos_so_com_alt(qapp):
    theme.apply_app(qapp)
    st = QApplication.style()
    assert st.styleHint(QStyle.StyleHint.SH_UnderlineShortcut) == 0
    assert st.styleHint(QStyle.StyleHint.SH_MenuBar_AltKeyNavigation) == 1
    theme.set_mnemonics_visible(True)
    assert st.styleHint(QStyle.StyleHint.SH_UnderlineShortcut) == 1
    theme.set_mnemonics_visible(False)


def test_alt_na_janela_liga_e_desliga_o_sublinhado(win, qapp):
    """O filtro fica na QWindow da janela (nao no app inteiro) e ainda ve o Alt."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    win.show()
    qapp.processEvents()
    handle = win.windowHandle()
    QTest.keyPress(handle, Qt.Key.Key_Alt)
    assert theme._MNEMONICS_VISIBLE
    QTest.keyRelease(handle, Qt.Key.Key_Alt)
    QTest.mouseClick(handle, Qt.MouseButton.LeftButton)     # clique encerra o modo teclado
    qapp.processEvents()
    assert not theme._MNEMONICS_VISIBLE


def test_alto_contraste_ignorado_nos_testes():
    assert theme._high_contrast_palette() is None and not theme.HIGH_CONTRAST
