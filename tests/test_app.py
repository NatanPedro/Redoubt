"""Testes de integracao do app (MainWindow/CodeEditor) — headless (offscreen)."""

import os

import pytest
from PyQt6.QtWidgets import QApplication

from notepy import vault
from notepy.editor import read_text

SECRET_FILE = 'AWS = "AKIA3FK7XQ2MNP8RTUVW"\nsenha: batata123'


# --------------------------------------------------------------------------- #
# Cofre: selar -> gravar cifrado -> reabrir
# --------------------------------------------------------------------------- #
def test_selar_grava_cifrado_e_reabre(win, tmp_path):
    ed = win.current_editor()
    ed.setText("conta: x\nsenha: y")
    win._inbox += [("pw1234", True), ("pw1234", True)]
    win.seal_current()
    assert ed.is_vault

    vp = str(tmp_path / "c.rdbt")
    assert win._write(ed, vp)
    raw = open(vp, "rb").read()
    assert raw[:5] == b"RDBT1" and b"senha: y" not in raw

    # reabre com a senha certa
    win._inbox.append(("pw1234", True))
    win._open_vault(vp)
    assert "senha: y" in win.current_editor().text()
    assert win.current_editor().is_vault


def test_reabrir_com_senha_errada_nao_abre(win, tmp_path):
    blob = vault.encrypt("segredo", "certa")
    vp = tmp_path / "c.rdbt"
    vp.write_bytes(blob)
    n0 = win.tabs.count()
    win._inbox.append(("errada", True))
    win._open_vault(str(vp))
    assert win.tabs.count() == n0   # nenhuma aba nova


def test_lock_unlock_preserva_conteudo(win):
    ed = win.current_editor()
    ed.setText(SECRET_FILE)
    win._inbox += [("master12", True), ("master12", True)]
    win.seal_current()
    assert ed.lock()
    assert ed.is_locked() and ed._vault_password is None
    assert "AKIA3FK7XQ2MNP8RTUVW" not in ed.text()   # escondido
    assert ed.unlock("master12")
    assert not ed.is_locked() and ed.text() == SECRET_FILE   # restaurado byte a byte


# --------------------------------------------------------------------------- #
# Redacao do clipboard (camada do clipboard)
# --------------------------------------------------------------------------- #
def test_clipboard_redacao(win):
    ed = win.current_editor()
    ed.setText('token = AKIA3FK7XQ2MNP8RTUVW')
    ed.set_redaction(True)
    ed._rescan_secrets()
    cb = QApplication.clipboard()

    cb.setText("AKIA3FK7XQ2MNP8RTUVW"); win._sanitize_clipboard()
    assert "AKIA3FK7XQ2MNP8RTUVW" not in cb.text()      # segredo inteiro mascarado

    cb.setText("AKIA3FK7"); win._sanitize_clipboard()
    assert "AKIA3FK7" not in cb.text()                  # copia PARCIAL mascarada

    cb.setText("texto comum de outro app"); win._sanitize_clipboard()
    assert cb.text() == "texto comum de outro app"      # alheio intacto

    ed.set_redaction(False)
    cb.setText("AKIA3FK7XQ2MNP8RTUVW"); win._sanitize_clipboard()
    assert "AKIA3FK7XQ2MNP8RTUVW" in cb.text()          # redacao OFF -> real


def test_clipboard_redacao_protege_com_aba_nao_redigida_em_foco(win):
    # REGRESSAO (pentest v0.6): a aba DONA da copia nao e sempre a focada. Com 2+
    # abas, copiar de uma aba redigida vazava se a aba em foco nao estivesse redigida.
    a = win.current_editor()
    a.setText('token = AKIA3FK7XQ2MNP8RTUVW')
    a.set_redaction(True); a._rescan_secrets()
    win.new_file()                                      # aba B (sem redacao) vira a focada
    assert win.current_editor() is not a
    cb = QApplication.clipboard()
    cb.setText("AKIA3FK7XQ2MNP8RTUVW"); win._sanitize_clipboard()
    assert "AKIA3FK7XQ2MNP8RTUVW" not in cb.text()      # mascarado pela aba A redigida


def test_lock_esvazia_undo(win):
    # REGRESSAO (pentest v0.6): sem esvaziar o undo, Ctrl+Z reconstruia o texto-claro
    # anterior ao travamento.
    ed = win.current_editor()
    ed.setText("api_key = AKIA3FK7XQ2MNP8RTUVW")
    ed.insertAt(" x", 0, 0)                             # cria historico de undo
    assert ed.SendScintilla(ed.SCI_CANUNDO)
    ed.is_vault = True
    ed._vault_password = "master12"
    assert ed.lock()
    assert not ed.SendScintilla(ed.SCI_CANUNDO)         # lock zerou o undo


# --------------------------------------------------------------------------- #
# Burn note
# --------------------------------------------------------------------------- #
def test_burn_nao_salva_e_apaga(win):
    win.new_burn()
    b = win.current_editor()
    assert b.is_burn
    b.setText("segredo efemero")
    assert win.save_file(b) is False        # bloqueado (nao vai pro disco)
    win._wipe_editor(b)
    assert b.text() == ""                   # apagado


# --------------------------------------------------------------------------- #
# Selo: estados
# --------------------------------------------------------------------------- #
def test_selo_estados(win):
    ed = win.current_editor()
    ed.setText("texto limpo"); ed._rescan_secrets(); win._update_status()
    assert "LIMPO" in win.lbl_seal.text()
    ed.setText('k = "AKIA3FK7XQ2MNP8RTUVW"'); ed._rescan_secrets(); win._update_status()
    assert "EXPOSTO" in win.lbl_seal.text()


# --------------------------------------------------------------------------- #
# Mapa de exposicao (marcador na margem da linha com segredo)
# --------------------------------------------------------------------------- #
def test_mapa_de_exposicao(win):
    ed = win.current_editor()
    ed.setText('limpa\nAWS = "AKIA3FK7XQ2MNP8RTUVW"\noutra')
    ed._rescan_secrets()
    assert ed.markersAtLine(0) == 0          # linha 0 sem marcador
    assert ed.markersAtLine(1) & 1           # linha 1 (segredo) marcada


# --------------------------------------------------------------------------- #
# Deteccao de encoding / BOM (read_text)
# --------------------------------------------------------------------------- #
def test_encoding_detection(tmp_path):
    plain = tmp_path / "a.txt"
    plain.write_bytes("ação coração".encode("utf-8"))
    assert read_text(str(plain))[1] == "utf-8"            # UTF-8 puro NAO vira BOM

    bom = tmp_path / "b.txt"
    bom.write_bytes(b"\xef\xbb\xbf" + "com bom".encode("utf-8"))
    assert read_text(str(bom))[1] == "utf-8-sig"          # so com BOM real


def test_read_text_utf16_decodifica_e_e_varrivel(tmp_path):
    # REGRESSAO (pentest v0.6): UTF-16 caia em cp1252/latin-1 (mojibake) e o
    # segredo ficava invisivel -> selo "LIMPO" falso.
    from notepy import secrets
    f = tmp_path / "u16.txt"
    f.write_bytes("senha = AKIA3FK7XQ2MNP8RTUVW".encode("utf-16"))
    text, enc = read_text(str(f))
    assert enc == "utf-16"
    assert "AKIA3FK7XQ2MNP8RTUVW" in text                  # decodificado certo
    assert len(secrets.scan(text)) >= 1                    # e a Sentinela enxerga


def test_read_text_nul_nao_trunca(tmp_path):
    # REGRESSAO (pentest v0.6): SCI_SETTEXT trunca no \x00 -> conteudo (e segredo)
    # apos o NUL sumia e o selo mostrava "LIMPO".
    from notepy import secrets
    f = tmp_path / "nul.txt"
    f.write_bytes(b"antes\x00AKIA3FK7XQ2MNP8RTUVW\x00depois")
    text, _ = read_text(str(f))
    assert "\x00" not in text                              # NUL neutralizado (vira ␀)
    assert "AKIA3FK7XQ2MNP8RTUVW" in text                  # conteudo apos o NUL preservado
    assert len(secrets.scan(text)) >= 1
