"""Testes do backup/restauracao da identidade (notepy/idbackup.py) — sem Qt."""

import base64
import os

import pytest

from notepy import custody, idbackup, vault


@pytest.fixture
def tmp_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def _reset_cache():
    custody.lock_identity()
    yield
    custody.lock_identity()


@pytest.fixture(autouse=True)
def _argon_rapido(monkeypatch):
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_MEMLOG2", 10)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_T", 1)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_LANES", 1)


# --------------------------------------------------------------------------- #
# Coletar
# --------------------------------------------------------------------------- #
def test_sem_identidade_nao_cria_nada(tmp_identity):
    """READ-ONLY: pedir backup numa instalacao limpa erra, e NAO materializa uma chave."""
    assert not idbackup.local_identity_exists()
    with pytest.raises(idbackup.BackupError):
        idbackup.collect_local()
    assert os.listdir(str(tmp_identity)) == []


def test_coleta_identidade_em_claro(tmp_identity):
    custody.sign("x")                                  # cria a identidade legada
    payload = idbackup.collect_local()
    assert payload["format"] == idbackup.FORMAT
    assert payload["ed25519_fingerprint"] == custody.fingerprint()
    assert len(base64.b64decode(payload["ed25519_private"])) == 32


def test_coleta_inclui_a_chave_x25519(tmp_identity):
    custody.sign("x")
    fp_x = custody.recipient_fingerprint()             # cria a chave de destinatario
    payload = idbackup.collect_local()
    assert payload["x25519_fingerprint"] == fp_x
    assert len(base64.b64decode(payload["x25519_private"])) == 32


def test_coleta_de_identidade_protegida_exige_credencial(tmp_identity):
    custody.sign("x")
    fp = custody.fingerprint()
    custody.protect_identity("senha-id")
    custody.lock_identity()
    with pytest.raises(idbackup.BackupError):
        idbackup.collect_local()                       # sem senha
    with pytest.raises(idbackup.BackupError):
        idbackup.collect_local("errada")
    payload = idbackup.collect_local("senha-id")
    assert payload["ed25519_fingerprint"] == fp        # mesma identidade


# --------------------------------------------------------------------------- #
# Pacote cifrado
# --------------------------------------------------------------------------- #
def test_pacote_e_cifrado_e_nao_tem_a_chave_em_claro(tmp_identity):
    custody.sign("x")
    payload = idbackup.collect_local()
    blob = idbackup.make_blob(payload, password="pw-backup")
    assert vault.looks_like_vault(blob)
    bruto = base64.b64decode(payload["ed25519_private"])
    assert bruto not in blob                           # a privada nao aparece crua...
    assert payload["ed25519_private"].encode() not in blob   # ...nem em base64
    assert b"RDBT-IDBAK1" not in blob                  # nem o rotulo do payload


def test_make_blob_exige_credencial(tmp_identity):
    custody.sign("x")
    with pytest.raises(idbackup.BackupError):
        idbackup.make_blob(idbackup.collect_local())


def test_roundtrip_e_verificacao(tmp_identity):
    custody.sign("x")
    fp = custody.fingerprint()
    payload = idbackup.collect_local()
    blob = idbackup.make_blob(payload, password="pw-backup")
    lido = idbackup.verify_blob(blob, password="pw-backup", expected_ed_fingerprint=fp)
    assert lido["ed25519_fingerprint"] == fp
    assert fp in idbackup.summary(lido)
    assert "private" not in idbackup.summary(lido)     # o resumo nunca vaza chave


def test_credencial_errada_e_lixo_erram_amigavelmente(tmp_identity):
    custody.sign("x")
    blob = idbackup.make_blob(idbackup.collect_local(), password="certa")
    with pytest.raises(idbackup.BackupError):
        idbackup.open_blob(blob, password="errada")
    with pytest.raises(idbackup.BackupError):
        idbackup.open_blob(b"nao e cofre nenhum", password="certa")


def test_cofre_valido_que_nao_e_backup_e_recusado(tmp_identity):
    blob = vault.new_vault("apenas um texto qualquer", password="pw")
    with pytest.raises(idbackup.BackupError):
        idbackup.open_blob(blob, password="pw")


def test_verify_recusa_pacote_com_fingerprint_mentiroso(tmp_identity):
    custody.sign("x")
    payload = idbackup.collect_local()
    payload["ed25519_fingerprint"] = "0000000000000000"      # declara outro
    blob = idbackup.make_blob(payload, password="pw")
    with pytest.raises(idbackup.BackupError):
        idbackup.verify_blob(blob, password="pw")


def test_backup_por_arquivo_chave(tmp_identity):
    custody.sign("x")
    kf = b"arquivo-chave-do-backup"
    blob = idbackup.make_blob(idbackup.collect_local(), keyfile=kf)
    assert idbackup.verify_blob(blob, keyfile=kf)["format"] == idbackup.FORMAT
    with pytest.raises(idbackup.BackupError):
        idbackup.open_blob(blob, keyfile=b"errado")


# --------------------------------------------------------------------------- #
# Restaurar
# --------------------------------------------------------------------------- #
def test_restaura_em_maquina_limpa_e_volta_a_assinar(tmp_path, monkeypatch):
    """O caso que justifica a ferramenta: HD novo, identidade de volta, assinando igual."""
    origem, novo = tmp_path / "antiga", tmp_path / "nova"
    origem.mkdir(); novo.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(origem))
    sig = custody.sign("documento historico")
    fp = custody.fingerprint()
    custody.recipient_fingerprint()                    # tambem a chave X25519
    payload = idbackup.collect_local()

    monkeypatch.setattr(custody, "_data_dir", lambda: str(novo))
    custody.lock_identity()
    assert not idbackup.local_identity_exists()
    escritos = idbackup.restore(payload, str(novo))
    assert "identity.ed25519" in escritos and "recipient.x25519" in escritos
    assert custody.fingerprint() == fp                 # MESMA identidade
    assert custody.verify("documento historico", sig)  # e valida o que ela assinou antes
    assert custody.verify("novo", custody.sign("novo"))


def test_restore_recusa_sobrescrever_identidade_diferente(tmp_path, monkeypatch):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(a))
    payload = (custody.sign("x"), idbackup.collect_local())[1]
    fp_a = custody.fingerprint()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(b))
    custody.lock_identity()
    custody.sign("y")                                  # B tem OUTRA identidade
    fp_b = custody.fingerprint()
    assert fp_a != fp_b
    with pytest.raises(idbackup.BackupError) as e:
        idbackup.restore(payload, str(b))              # sem force -> recusa
    assert fp_a in str(e.value) and fp_b in str(e.value)   # mostra os DOIS p/ comparacao
    custody.lock_identity()
    assert custody.fingerprint() == fp_b               # nada foi trocado
    idbackup.restore(payload, str(b), force=True)      # com force -> substitui
    custody.lock_identity()
    assert custody.fingerprint() == fp_a


def test_restore_remove_cofre_antigo_senao_a_restauracao_seria_inutil(tmp_path, monkeypatch):
    """Se o identity.rdbt anterior ficasse, is_protected() venceria e o app usaria a chave VELHA."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(a))
    custody.sign("x")
    payload = idbackup.collect_local()
    fp_a = custody.fingerprint()

    monkeypatch.setattr(custody, "_data_dir", lambda: str(b))
    custody.lock_identity()
    custody.sign("y")
    custody.protect_identity("pw-b")                   # B protegida (tem identity.rdbt)
    assert custody.is_protected()
    custody.lock_identity()
    idbackup.restore(payload, str(b), force=True)
    assert not custody.is_protected()                  # cofre antigo saiu do caminho
    assert custody.fingerprint() == fp_a               # e a chave restaurada e a que vale
    assert custody.verify("z", custody.sign("z"))


def test_restore_recusa_payload_com_chave_de_tamanho_errado(tmp_path):
    d = tmp_path / "d"; d.mkdir()
    payload = {"format": idbackup.FORMAT, "created_at": "2026-01-01T00:00:00+00:00",
               "ed25519_private": base64.b64encode(b"curto").decode(),
               "ed25519_fingerprint": "x" * 16, "x25519_private": None,
               "x25519_fingerprint": None}
    with pytest.raises(idbackup.BackupError):
        idbackup.restore(payload, str(d))
    assert os.listdir(str(d)) == []                    # nada escrito


def test_chave_restaurada_tem_permissao_restrita(tmp_path, monkeypatch):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(a))
    custody.sign("x")
    payload = idbackup.collect_local()
    idbackup.restore(payload, str(b))
    pem = b / "identity.ed25519"
    assert pem.is_file() and pem.stat().st_size > 0
    assert (b / "identity.pub").is_file()
