"""Credenciais e backup da identidade pela janela: trocar senha, adicionar arquivo-chave, remover
credencial, backup cifrado (e a oferta de backup logo depois de proteger).

Os dialogos sao substituidos: senhas vem da fila `win._inbox` (QInputDialog.getText, ver conftest),
e pastas/arquivos/escolhas por monkeypatch em cada teste."""

import os

import pytest
from PyQt6.QtWidgets import QFileDialog, QInputDialog, QMessageBox

from notepy import custody, idbackup, vault, widgets

YES, NO = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No


@pytest.fixture(autouse=True)
def _argon_rapido(monkeypatch):
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_MEMLOG2", 10)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_T", 1)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_LANES", 1)
    custody.lock_identity()
    custody.lock_recipient()
    yield
    custody.lock_identity()
    custody.lock_recipient()


@pytest.fixture
def ident(tmp_path, monkeypatch):
    """Identidade em pasta temporaria + uma pasta de 'pendrive'."""
    data = tmp_path / "data"
    data.mkdir()
    pen = tmp_path / "pendrive"
    pen.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(data))
    custody.sign("x")                                       # cria a identidade (em claro)
    return data, pen


def _protegida(senha="antiga"):
    custody.protect_identity(senha)
    custody.lock_identity()


def _avisos(monkeypatch):
    """Captura information/warning/critical (o conftest so os neutraliza)."""
    vistos = []
    for nome in ("information", "warning", "critical"):
        monkeypatch.setattr(QMessageBox, nome, staticmethod(
            lambda *a, _n=nome, **k: vistos.append((_n, a[2] if len(a) > 2 else "")) or
            QMessageBox.StandardButton.Ok))
    return vistos


def _backups(pen):
    return [p for p in os.listdir(pen) if p.endswith(".rdbtbak")]


# --------------------------------------------------------------------------- #
# Proteger -> oferece o backup na hora
# --------------------------------------------------------------------------- #
def test_proteger_oferece_o_backup_e_grava_no_pendrive(win, ident, monkeypatch):
    _, pen = ident
    fp = custody.fingerprint()
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: YES))
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: str(pen)))
    win._inbox += [("senha-id", True), ("senha-id", True),      # proteger
                   ("senha-bk", True), ("senha-bk", True)]      # senha DO backup (sem pedir a da id)
    win.protect_identity()
    assert custody.is_protected()
    (nome,) = _backups(pen)
    payload = idbackup.verify_blob((pen / nome).read_bytes(), password="senha-bk",
                                   expected_ed_fingerprint=fp)
    assert payload["ed25519_fingerprint"] == fp
    assert win._inbox == []                                    # nenhuma senha a mais foi pedida


def test_proteger_e_recusar_o_backup_nao_grava_nada(win, ident, monkeypatch):
    _, pen = ident
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: NO))
    monkeypatch.setattr(QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: pytest.fail("recusou: nao pede pasta")))
    win._inbox += [("senha-id", True), ("senha-id", True)]
    win.protect_identity()
    assert custody.is_protected() and _backups(pen) == []


# --------------------------------------------------------------------------- #
# Trocar senha
# --------------------------------------------------------------------------- #
def test_trocar_senha_pelo_menu(win, ident, monkeypatch):
    _protegida("antiga")
    fp = custody.fingerprint()
    win._inbox += [("antiga", True), ("nova-1", True), ("nova-1", True)]
    win.change_identity_password()
    assert custody.unlock_identity("antiga") is False
    assert custody.unlock_identity("nova-1") and custody.fingerprint() == fp


def test_trocar_senha_com_a_atual_errada_avisa_e_nao_muda(win, ident, monkeypatch):
    _protegida("antiga")
    vistos = _avisos(monkeypatch)
    win._inbox += [("errada", True), ("nova-1", True), ("nova-1", True)]
    win.change_identity_password()
    assert ("warning", "Senha atual incorreta. Nada mudou.") in vistos
    assert custody.unlock_identity("antiga")


def test_trocar_senha_com_confirmacao_diferente_nao_muda(win, ident, monkeypatch):
    _protegida("antiga")
    win._inbox += [("antiga", True), ("nova-1", True), ("nova-2", True)]
    win.change_identity_password()
    assert custody.unlock_identity("antiga")


# --------------------------------------------------------------------------- #
# Arquivo-chave: gerado no pendrive, nunca ao lado do cofre
# --------------------------------------------------------------------------- #
def _escolher(monkeypatch, prefixo):
    """O QMessageBox proprio (Gerar novo / Usar existente) 'clica' no botao pelo texto."""
    def exec_(self):
        next(b for b in self.buttons() if b.text().startswith(prefixo)).click()
        return 0
    monkeypatch.setattr(QMessageBox, "exec", exec_)


def test_adicionar_arquivo_chave_gerado_no_pendrive(win, ident, monkeypatch):
    _, pen = ident
    _protegida("antiga")
    alvo = pen / "id.keyfile"
    _escolher(monkeypatch, "Gerar")
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(alvo), "")))
    win._inbox += [("antiga", True)]
    win.add_identity_keyfile()
    kf = alvo.read_bytes()
    assert len(kf) == 64
    assert custody.identity_unlockers() == [vault.KIND_PASSWORD, vault.KIND_KEYFILE]
    assert custody.unlock_identity(keyfile=kf)


def test_arquivo_chave_na_pasta_de_dados_e_recusado(win, ident, monkeypatch):
    data, _ = ident
    _protegida("antiga")
    vistos = _avisos(monkeypatch)
    _escolher(monkeypatch, "Gerar")
    monkeypatch.setattr(QFileDialog, "getSaveFileName",
                        staticmethod(lambda *a, **k: (str(data / "id.keyfile"), "")))
    win._inbox += [("antiga", True)]
    win.add_identity_keyfile()
    assert not (data / "id.keyfile").exists()
    assert custody.identity_unlockers() == [vault.KIND_PASSWORD]
    assert any(n == "warning" and "pasta de dados" in m for n, m in vistos)


def test_adicionar_arquivo_chave_existente(win, ident, monkeypatch, tmp_path):
    _protegida("antiga")
    kf = tmp_path / "meu.key"
    kf.write_bytes(b"conteudo-do-arquivo-chave")
    _escolher(monkeypatch, "Usar")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(kf), "")))
    win._inbox += [("antiga", True)]
    win.add_identity_keyfile()
    assert custody.unlock_identity(keyfile=b"conteudo-do-arquivo-chave")


# --------------------------------------------------------------------------- #
# Remover credencial: entra com uma que fica
# --------------------------------------------------------------------------- #
def test_remover_a_senha_entrando_com_o_arquivo_chave(win, ident, monkeypatch, tmp_path):
    _protegida("antiga")
    custody.add_identity_unlocker(passphrase="antiga", new_keyfile=b"kf-que-fica")
    kf = tmp_path / "fica.key"
    kf.write_bytes(b"kf-que-fica")
    monkeypatch.setattr(QInputDialog, "getItem", staticmethod(lambda *a, **k: ("1. Senha", True)))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(kf), "")))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: YES))
    win.remove_identity_credential()
    assert custody.identity_unlockers() == [vault.KIND_KEYFILE]
    assert custody.unlock_identity("antiga") is False


def test_remover_com_uma_credencial_so_avisa_e_nao_mexe(win, ident, monkeypatch):
    _protegida("antiga")
    vistos = _avisos(monkeypatch)
    monkeypatch.setattr(QInputDialog, "getItem",
                        staticmethod(lambda *a, **k: pytest.fail("uma credencial so: nem pergunta")))
    win.remove_identity_credential()
    assert custody.identity_unlockers() == [vault.KIND_PASSWORD]
    assert any(n == "information" and "credencial so" in m for n, m in vistos)


def test_remover_e_desistir_na_confirmacao_nao_mexe(win, ident, monkeypatch):
    _protegida("antiga")
    custody.add_identity_unlocker(passphrase="antiga", new_password="segunda")
    monkeypatch.setattr(QInputDialog, "getItem", staticmethod(lambda *a, **k: ("2. Senha", True)))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: NO))
    win._inbox += [("antiga", True)]
    win.remove_identity_credential()
    assert custody.identity_unlockers() == [vault.KIND_PASSWORD, vault.KIND_PASSWORD]


# --------------------------------------------------------------------------- #
# Backup pelo menu e pelo painel de Custodia
# --------------------------------------------------------------------------- #
def test_backup_pelo_menu_de_identidade_protegida(win, ident, monkeypatch):
    _, pen = ident
    _protegida("antiga")
    fp = custody.fingerprint()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: str(pen)))
    win._inbox += [("antiga", True), ("senha-bk", True), ("senha-bk", True)]
    win.backup_identity()
    (nome,) = _backups(pen)
    assert idbackup.verify_blob((pen / nome).read_bytes(), password="senha-bk",
                                expected_ed_fingerprint=fp)


def test_backup_com_a_senha_da_identidade_errada_nao_grava(win, ident, monkeypatch):
    _, pen = ident
    _protegida("antiga")
    vistos = _avisos(monkeypatch)
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: str(pen)))
    win._inbox += [("errada", True)]
    win.backup_identity()
    assert _backups(pen) == [] and any(n == "warning" for n, _ in vistos)


def test_menu_so_habilita_o_que_faz_sentido(win, ident):
    win._refresh_identity_actions()                             # em claro
    assert not win.act_id_change_pw.isEnabled() and win.act_id_backup.isEnabled()
    _protegida("antiga")
    win._refresh_identity_actions()
    assert all(a.isEnabled() for a in (win.act_id_change_pw, win.act_id_add_pw,
                                       win.act_id_add_keyfile, win.act_id_remove))


def test_painel_de_custodia_tem_o_botao_de_backup(win):
    r = widgets.CustodyReport(
        name="a.txt", sha256="0" * 64, content_state="ok", signature_state="ok",
        signature_file="a.txt.sig", fingerprint="f2478010e453b42f", public_key="x",
        identity_protected=True, warnings=[], chain_ok=True, chain_break_at=-1,
        events_total=1, events_signed=1, recent=[])
    chamado = []
    dlg = widgets.CustodyDialog(r, {"backup_identity": lambda: chamado.append(1)})
    from PyQt6.QtWidgets import QPushButton
    (btn,) = [b for b in dlg.findChildren(QPushButton) if b.objectName() == "CustodyBackup"]
    btn.click()
    assert chamado == [1]
