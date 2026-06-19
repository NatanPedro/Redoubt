"""Testes de integracao do app (MainWindow/CodeEditor) — headless (offscreen)."""

import os

import pytest
from PyQt6.QtWidgets import QApplication

from notepy import vault
from notepy.editor import read_text

SECRET_FILE = 'AWS = "AKIA3FK7XQ2MNP8RTUVW"\nsenha: batata123'


@pytest.fixture(autouse=True)
def _argon_rapido(monkeypatch):
    """O Cofre usa Argon2id; params leves p/ os testes de cofre rodarem rapido. Tambem isola
    a Lista de redacao (global de modulo) — nenhum teste herda a lista destravada de outro."""
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_MEMLOG2", 10)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_T", 1)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_LANES", 1)
    yield
    from notepy import redaction
    redaction.lock()


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
    assert raw[:5] == b"RDBT3" and b"senha: y" not in raw   # envelope RDBT3 (Argon2id)

    # reabre com a senha certa
    win._inbox.append(("pw1234", True))
    win._open_vault(vp)
    assert "senha: y" in win.current_editor().text()
    assert win.current_editor().is_vault


def test_cofre_adiciona_senha_e_abre_com_ela(win, tmp_path):
    # Cofre++: 2a senha independente abre o MESMO cofre, e sobrevive ao salvar.
    ed = win.current_editor(); ed.setText("conteudo do cofre")
    win._inbox += [("senha-A", True), ("senha-A", True)]    # selar
    assert win.seal_current()
    win._inbox += [("senha-B", True), ("senha-B", True)]    # adicionar 2a senha
    win.add_vault_password()
    vp = str(tmp_path / "c.rdbt")
    assert win._write(ed, vp)
    win._inbox.append(("senha-B", True))                    # reabre com a 2a senha
    win._open_vault(vp)
    assert "conteudo do cofre" in win.current_editor().text()


def test_cofre_keyfile_adiciona_e_destrava(win, tmp_path, monkeypatch):
    # Cofre++: arquivo-chave adicionado destrava o cofre (sem senha).
    from PyQt6.QtWidgets import QFileDialog
    kf = tmp_path / "chave.key"; kf.write_bytes(b"material-de-arquivo-chave-1234567890")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(kf), "")))
    ed = win.current_editor(); ed.setText("guardado a sete chaves")
    win._inbox += [("senhaX", True), ("senhaX", True)]
    assert win.seal_current()
    win.add_vault_keyfile()                                  # adiciona slot de arquivo-chave
    assert win._write(ed, str(tmp_path / "c.rdbt"))
    assert ed.lock()
    win.unlock_with_keyfile()                                # destrava SO com o arquivo-chave
    assert not ed.is_locked() and "guardado a sete chaves" in ed.text()


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
    assert ed.is_locked() and ed._vault_key is None  # zero-knowledge: esqueceu a chave
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


# --------------------------------------------------------------------------- #
# Restaurar sessao (so caminhos; nunca conteudo)
# --------------------------------------------------------------------------- #
def _temp_settings(monkeypatch, tmp_path):
    from PyQt6.QtCore import QSettings
    from notepy import config
    s = QSettings(str(tmp_path / "prefs.ini"), QSettings.Format.IniFormat)
    monkeypatch.setattr(config, "_s", lambda: s)
    return s


def test_sessao_salva_so_caminhos_sem_conteudo(win, tmp_path, monkeypatch):
    from notepy import config
    s = _temp_settings(monkeypatch, tmp_path)
    f = tmp_path / "a.txt"
    f.write_text("oi AKIA3FK7XQ2MNP8RTUVW", encoding="utf-8")
    win.open_path(str(f))
    win.new_burn(); win.current_editor().setText("BURN-SECRETO-9988")   # nao pode persistir
    win._save_session()
    paths, _ = config.load_session()
    assert any(p.endswith("a.txt") for p in paths)          # arquivo real entra
    assert all("BURN" not in p for p in paths)              # burn fora
    # e o armazenamento (registro/.ini) NAO contem conteudo nenhum:
    s.sync()
    raw = open(s.fileName(), encoding="utf-8", errors="replace").read()
    assert "BURN-SECRETO-9988" not in raw
    assert "AKIA3FK7XQ2MNP8RTUVW" not in raw


def test_restaura_arquivo_e_cofre_travado(win, tmp_path, monkeypatch):
    from notepy import config, vault
    _temp_settings(monkeypatch, tmp_path)
    f = tmp_path / "a.txt"; f.write_text("conteudo", encoding="utf-8")
    v = tmp_path / "c.rdbt"; v.write_bytes(vault.encrypt("segredo guardado", "pw1234"))
    config.save_session([str(f), str(v)], 0)
    win.restore_session()
    nomes = [win.tabs.widget(i).path for i in range(win.tabs.count())]
    assert any(n and n.endswith("a.txt") for n in nomes)
    vtab = next(w for i in range(win.tabs.count())
                if (w := win.tabs.widget(i)).is_vault)
    assert vtab.is_locked() and vtab._vault_password is None    # zero-knowledge: sem senha
    assert vtab.unlock("pw1234") and "segredo guardado" in vtab.text()


def test_restore_desligado_nao_reabre(win, tmp_path, monkeypatch):
    from notepy import config
    _temp_settings(monkeypatch, tmp_path)
    f = tmp_path / "a.txt"; f.write_text("x", encoding="utf-8")
    config.save_session([str(f)], 0)
    config.set_("restore_session", False)
    assert win.restore_session() == 0


# --------------------------------------------------------------------------- #
# Conteudo OCULTO (gated): arquivo restaurado com credencial
# --------------------------------------------------------------------------- #
def test_restaura_credencial_fica_oculto_e_limpo_abre(win, tmp_path):
    f = tmp_path / "cred.txt"
    f.write_text("api_key = AKIA3FK7XQ2MNP8RTUVW\n", encoding="utf-8")
    g = tmp_path / "plain.txt"
    g.write_text("apenas texto comum sem nada\n", encoding="utf-8")
    win._restore_one(str(f))
    win._restore_one(str(g))
    cred = next(w for i in range(win.tabs.count())
                if (w := win.tabs.widget(i)).path == os.path.abspath(str(f)))
    plain = next(w for i in range(win.tabs.count())
                 if (w := win.tabs.widget(i)).path == os.path.abspath(str(g)))
    assert cred.is_gated() and cred.gated_count() >= 1
    assert "AKIA3FK7XQ2MNP8RTUVW" not in cred.text()              # oculto na tela
    assert "AKIA3FK7XQ2MNP8RTUVW" in (cred._gated_text or "")      # real so em RAM
    assert not plain.is_gated() and "texto comum" in plain.text()  # limpo abre normal


def test_revelar_mostra_e_varre(win, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("k = AKIA3FK7XQ2MNP8RTUVW\n", encoding="utf-8")
    win._restore_one(str(f))
    ed = next(w for i in range(win.tabs.count()) if (w := win.tabs.widget(i)).is_gated())
    win.tabs.setCurrentWidget(ed)
    win._update_gate_bar()
    assert not win.gate_bar.isHidden()                  # barra aparece quando oculto
    win.reveal_current()
    assert not ed.is_gated()
    assert "AKIA3FK7XQ2MNP8RTUVW" in ed.text()          # conteudo revelado
    assert len(ed.secret_matches()) >= 1               # Sentinela passa a marcar
    assert win.gate_bar.isHidden()                      # barra some apos revelar


def test_oculto_bloqueia_salvar_e_preserva_original(win, tmp_path):
    f = tmp_path / "c.txt"
    original = "k = AKIA3FK7XQ2MNP8RTUVW\n"
    f.write_text(original, encoding="utf-8")
    win._restore_one(str(f))
    ed = next(w for i in range(win.tabs.count()) if (w := win.tabs.widget(i)).is_gated())
    assert win.save_file(ed) is False                   # salvar bloqueado enquanto oculto
    assert f.read_text(encoding="utf-8") == original     # original NAO foi sobrescrito


def test_selar_oculto_vira_cofre(win, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("k = AKIA3FK7XQ2MNP8RTUVW\n", encoding="utf-8")
    win._restore_one(str(f))
    ed = next(w for i in range(win.tabs.count()) if (w := win.tabs.widget(i)).is_gated())
    win.tabs.setCurrentWidget(ed)
    win._inbox += [("pw1234", True), ("pw1234", True)]
    win._gate_seal()
    assert ed.is_vault and not ed.is_gated()


# --------------------------------------------------------------------------- #
# Tema (claro/escuro) e hook na GUI
# --------------------------------------------------------------------------- #
def test_apply_theme_troca_ao_vivo(win, tmp_path, monkeypatch):
    from notepy import config, theme
    _temp_settings(monkeypatch, tmp_path)
    try:
        config.set_("theme", "light")
        win.apply_theme()
        assert theme.current_theme() == "light"
        config.set_("theme", "dark")
        win.apply_theme()
        assert theme.current_theme() == "dark"
    finally:
        theme.set_theme("dark")


def test_restaura_cofre_adulterado_nao_crasha(win, tmp_path, monkeypatch):
    # REGRESSAO (pentest): blob .rdbt truncado/adulterado restaurado -> unlock so
    # capturava WrongPassword; VaultError escapava do slot Qt e derrubava o app.
    from notepy import config
    _temp_settings(monkeypatch, tmp_path)
    bad = tmp_path / "trunc.rdbt"
    bad.write_bytes(b"RDBT1" + bytes([1, 15, 8, 1]) + b"\x00\x00\x00")   # MAGIC ok, resto invalido
    config.save_session([str(bad)], 0)
    win.restore_session()
    vtab = next(w for i in range(win.tabs.count()) if (w := win.tabs.widget(i)).is_vault)
    assert vtab.is_locked()
    win.tabs.setCurrentWidget(vtab)
    win._inbox.append(("qualquer", True))
    win.unlock_current()                       # NAO pode levantar (VaultError tratado)
    assert vtab.is_locked()                    # segue travado, app vivo


def test_restaura_arquivo_grande_fica_oculto(win, tmp_path, monkeypatch):
    # REGRESSAO (pentest): arquivo > limite era aberto EM CLARO (fail-open). Agora
    # oculta por precaucao (fail-safe) — nao joga conteudo na tela ao restaurar.
    from notepy import config
    _temp_settings(monkeypatch, tmp_path)
    big = tmp_path / "big.txt"
    big.write_text("x" * 2_000_001 + "\nAWS = AKIA3FK7XQ2MNP8RTUVW\n", encoding="utf-8")
    config.save_session([str(big)], 0)
    win.restore_session()
    ed = next(w for i in range(win.tabs.count())
              if (w := win.tabs.widget(i)).path == os.path.abspath(str(big)))
    assert ed.is_gated()
    assert "AKIA3FK7XQ2MNP8RTUVW" not in ed.text()


def test_gate_seal_cancelar_mantem_oculto(win, tmp_path):
    # REGRESSAO (pentest): _gate_seal revelava ANTES de pedir senha -> cancelar
    # deixava o segredo exposto. Agora pede senha com a aba ainda oculta.
    f = tmp_path / "c.txt"
    f.write_text("k = AKIA3FK7XQ2MNP8RTUVW\n", encoding="utf-8")
    win._restore_one(str(f))
    ed = next(w for i in range(win.tabs.count()) if (w := win.tabs.widget(i)).is_gated())
    win.tabs.setCurrentWidget(ed)
    win._inbox.append(("", False))             # cancela o dialogo de senha
    win._gate_seal()
    assert ed.is_gated()                       # permanece OCULTO
    assert "AKIA3FK7XQ2MNP8RTUVW" not in ed.text()


def test_content_hash_oculto_usa_conteudo_real(win, tmp_path):
    import hashlib
    f = tmp_path / "c.txt"
    f.write_text("k = AKIA3FK7XQ2MNP8RTUVW\n", encoding="utf-8")
    win._restore_one(str(f))
    ed = next(w for i in range(win.tabs.count()) if (w := win.tabs.widget(i)).is_gated())
    esperado = hashlib.sha256(ed._gated_text.encode("utf-8", "surrogatepass")).hexdigest()
    assert ed.content_hash() == esperado       # custodia reflete o conteudo real, nao o banner


def test_write_bloqueia_aba_oculta(win, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("k = AKIA3FK7XQ2MNP8RTUVW\n", encoding="utf-8")
    win._restore_one(str(f))
    ed = next(w for i in range(win.tabs.count()) if (w := win.tabs.widget(i)).is_gated())
    out = tmp_path / "out.txt"
    assert win._write(ed, str(out)) is False   # chokepoint bloqueia (defesa em profundidade)
    assert not out.exists()


def _temp_identity(tmp_path, monkeypatch):
    from notepy import custody
    d = tmp_path / "identidade"
    d.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(d))
    return custody


def test_custodia_assina_e_verifica(win, tmp_path, monkeypatch):
    custody = _temp_identity(tmp_path, monkeypatch)
    ed = win.current_editor()
    ed.setText("documento de estado")
    f = tmp_path / "doc.txt"
    assert win._write(ed, str(f))                       # salva (+ evento "salvou")
    win.sign_and_export()
    sig_file = tmp_path / "doc.txt.sig"
    assert sig_file.exists()
    sig = sig_file.read_text(encoding="utf-8").strip()
    assert custody.verify(ed.custody_text(), sig)        # confere
    assert not custody.verify("documento ALTERADO", sig)  # adulteracao detectada


def test_custodia_trilha_encadeada_registra_eventos(win, tmp_path, monkeypatch):
    custody = _temp_identity(tmp_path, monkeypatch)
    ed = win.current_editor(); ed.setText("x")
    win._write(ed, str(tmp_path / "a.txt"))             # "salvou"
    win._wipe_editor(ed)                                # "queimou"
    eventos = [e["event"] for e in custody.read_audit()]
    assert "salvou" in eventos and "queimou" in eventos
    ok, idx = custody.verify_chain()
    assert ok and idx == -1                             # cadeia integra


def test_busca_em_arquivos_dialogo_e_abre_no_resultado(win, tmp_path):
    from notepy.mainwindow import SearchDialog
    (tmp_path / "doc.txt").write_text("linha1\nachar AKIA aqui\nlinha3", encoding="utf-8")
    # _open_at_line: abre o arquivo e pula para a linha
    win._open_at_line(str(tmp_path / "doc.txt"), 2)
    ed = win.current_editor()
    assert ed.path == os.path.abspath(str(tmp_path / "doc.txt"))
    assert ed.getCursorPosition()[0] == 1                    # linha 2 (0-based)
    # dialogo: run_search popula os resultados
    achados = []
    dlg = SearchDialog(lambda p, ln: achados.append((p, ln)), str(tmp_path))
    dlg.q.setText("achar")
    assert dlg.run_search() == 1


def test_paleta_commands_inclui_acoes_e_extras(win):
    labels = [lbl for lbl, _sc, _fn in win.palette_commands()]
    assert any("Salvar" in l for l in labels)
    assert any("cofre" in l.lower() for l in labels)
    assert any("Tema" in l for l in labels)                     # extra: tema claro/escuro
    assert any("oculto" in l.lower() for l in labels)           # extra: revelar oculto
    assert not any("Paleta de comandos" in l for l in labels)   # nao se auto-inclui


def test_paleta_filtra_e_executa(win):
    from notepy.mainwindow import CommandPalette
    fired = []
    dlg = CommandPalette([("Acao de Teste", "", lambda: fired.append(True))], win)
    dlg.edit.setText("teste")               # fuzzy casa "Acao de Teste"
    assert dlg.list.count() == 1
    dlg._run_current()                       # dispara o comando selecionado
    assert fired == [True]


def test_editor_nao_reivindica_override_das_teclas_do_app(qapp):
    # REGRESSAO: liberar o keymap nao bastava — o QScintilla ainda REIVINDICAVA a tecla
    # via ShortcutOverride, e a QAction Selar/Destravar nunca disparava. O editor agora
    # recusa o override das teclas reservadas (-> o atalho da janela dispara).
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtCore import QEvent, Qt
    from notepy.editor import CodeEditor
    ed = CodeEditor()
    M = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier
    ev = QKeyEvent(QEvent.Type.ShortcutOverride, Qt.Key.Key_L, M)   # Ctrl+Shift+L (selar)
    ed.event(ev)
    assert not ev.isAccepted()            # NAO reivindicou -> a QAction da janela dispara
    ev2 = QKeyEvent(QEvent.Type.ShortcutOverride, Qt.Key.Key_U, M)  # Ctrl+Shift+U (destravar)
    ed.event(ev2)
    assert not ev2.isAccepted()


def test_diff_dialog_compara_arquivos(win, tmp_path):
    from notepy.mainwindow import DiffDialog
    a = tmp_path / "a.txt"; a.write_text("linha1\nlinha2\nfim", encoding="utf-8")
    b = tmp_path / "b.txt"; b.write_text("linha1\nLINHA2X\nfim", encoding="utf-8")
    dlg = DiffDialog(str(a), win)
    dlg.b.setText(str(b))
    assert dlg.compare() > 0                                   # ha diferencas
    assert "LINHA2X" in dlg.view.toPlainText()                 # mostra a linha nova
    dlg.b.setText(str(a))
    dlg.compare()
    assert "identicos" in dlg.status.text().lower()            # A vs A = identico


def test_protect_repo_instala_hook_via_gui(win, tmp_path, monkeypatch):
    from PyQt6.QtWidgets import QFileDialog
    from notepy import scan_cli
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(parents=True)
    monkeypatch.setattr(QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: str(tmp_path)))
    monkeypatch.setattr(scan_cli, "_hooks_dir", lambda repo: str(hooks))
    win.protect_repo()
    assert (hooks / "pre-commit").exists()


def test_lista_de_redacao_tarja_no_editor(win, tmp_path, monkeypatch):
    """A Lista de redacao destravada faz o editor marcar o segredo LITERAL cadastrado —
    mesmo uma senha memoravel que a Sentinela (padrao/entropia) NAO pegaria sozinha."""
    from notepy import custody, redaction
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path))
    redaction.lock()
    redaction.init_new("pw")
    redaction.add("batata123")
    ed = win.current_editor()
    ed.setText("uma frase qualquer com batata123 no meio dela\n")
    ed.rescan_secrets()
    regs = [m for m in ed.secret_matches() if m.kind == "segredo registrado"]
    assert len(regs) == 1
    assert ed.text()[regs[0].start:regs[0].end] == "batata123"
    assert regs[0].snippet == "batata123"          # snippet = o segredo (cobre tarja + clipboard)
    redaction.lock()                                # travada -> editor deixa de marcar
    ed.rescan_secrets()
    assert not any(m.kind == "segredo registrado" for m in ed.secret_matches())


def test_lista_redacao_byte_spans_unicode(win, tmp_path, monkeypatch):
    """Regressao do red-team: a conversao char->byte (agora linear) mapeia certo com unicode
    multibyte + varios matches da lista."""
    from notepy import custody, redaction
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path))
    redaction.lock()
    redaction.init_new("pw")
    redaction.add("café")
    redaction.add("xyz9")
    ed = win.current_editor()
    ed.setText("café 日本 xyz9 café fim\n")
    ed.rescan_secrets()
    raw = ed.text().encode("utf-8", "surrogatepass")
    regs = [m for m in ed.secret_matches() if m.kind == "segredo registrado"]
    assert len(regs) == 3                            # café x2, xyz9 x1
    for bstart, blen, kind in ed._secret_byte_spans:
        if kind == "segredo registrado":
            assert raw[bstart:bstart + blen].decode("utf-8", "surrogatepass") in ("café", "xyz9")
    redaction.lock()


def test_lista_redacao_clipboard_fragmento_curto_mascarado(win, tmp_path, monkeypatch):
    """Regressao do red-team: copia PARCIAL (3 chars) de um segredo REGISTRADO curto e mascarada."""
    from notepy import custody, redaction
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path))
    redaction.lock()
    redaction.init_new("pw")
    redaction.add("PIN4")
    ed = win.current_editor()
    ed.setText("meu PIN4 aqui\n")
    ed.set_redaction(True)
    ed.rescan_secrets()
    cb = QApplication.clipboard()
    cb.setText("PIN")                                # fragmento de 3 chars do segredo
    win._sanitize_clipboard()
    assert cb.text() == "●●●"                        # mascarado (piso 2 p/ registrados)
    redaction.lock()


def test_dialog_lista_travada_nao_crasha(win, monkeypatch):
    """Regressao do red-team: gerenciar uma lista travada (ex.: auto-lock) avisa e fecha, sem levantar."""
    from PyQt6.QtWidgets import QMessageBox
    from notepy import redaction
    import notepy.mainwindow as mw
    redaction.lock()
    dlg = mw.RedactionListDialog(win)
    seen = {}
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: seen.setdefault("info", 1)))
    dlg._add()                                       # nao deve levantar VaultError
    assert seen.get("info") == 1
