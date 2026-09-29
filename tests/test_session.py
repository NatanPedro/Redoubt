"""Integridade da lista de sessao (notepy/session.py) e o caminho config -> session.

A lista vive nas configuracoes (no Windows, o registro), fora da pasta de dados: estes testes
garantem que quem so escreve ali nao escolhe mais o que o Redoubt reabre sozinho."""

import os
import stat
import sys

import pytest
from PyQt6.QtCore import QSettings

from notepy import config, custody, session

KEY = bytes(range(32))
PATHS = ["C:\\docs\\a.txt", "C:\\docs\\cofre.rdbt"] if os.name == "nt" else ["/docs/a.txt", "/docs/c.rdbt"]


@pytest.fixture
def isolado(tmp_path, monkeypatch):
    """Pasta de dados (onde fica a chave) e configuracoes (onde fica a lista) temporarias."""
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(data))
    s = QSettings(str(tmp_path / "prefs.ini"), QSettings.Format.IniFormat)
    monkeypatch.setattr(config, "_s", lambda: s)
    return data, s


# --------------------------------------------------------------------------- #
# Assinatura
# --------------------------------------------------------------------------- #
def test_assinatura_confere():
    tag = session.sign(KEY, PATHS, 1)
    assert session.check(PATHS, 1, tag, KEY) == session.OK


@pytest.mark.parametrize("paths,active", [
    ([*PATHS, "C:\\evil.txt"], 1),               # caminho acrescentado
    (PATHS[:1], 1),                              # caminho tirado
    (list(reversed(PATHS)), 1),                  # ordem trocada
    (PATHS, 0),                                  # aba ativa trocada
])
def test_qualquer_mudanca_na_lista_nao_confere(paths, active):
    tag = session.sign(KEY, PATHS, 1)
    assert session.check(paths, active, tag, KEY) == session.TAMPERED


def test_outra_chave_nao_confere():
    tag = session.sign(bytes(32), PATHS, 0)
    assert session.check(PATHS, 0, tag, KEY) == session.TAMPERED


def test_estados_sem_assinatura_ou_sem_chave():
    assert session.check([], 0, "", KEY) == session.EMPTY
    assert session.check(PATHS, 0, "", None) == session.LEGACY          # 1a vez depois de atualizar
    assert session.check(PATHS, 0, "", KEY) == session.TAMPERED         # tiraram a assinatura
    assert session.check(PATHS, 0, "ab" * 32, None) == session.TAMPERED  # nao ha como conferir


# --------------------------------------------------------------------------- #
# Chave
# --------------------------------------------------------------------------- #
def test_chave_criada_uma_vez_e_reusada(isolado):
    data, _ = isolado
    assert session.current_key() is None                 # ler nunca cria
    k1 = session.ensure_key()
    assert k1 is not None and len(k1) == session.KEY_LEN
    assert session.ensure_key() == k1 == session.current_key()
    assert (data / session.KEY_FILE).read_bytes() == k1


def test_chave_corrompida_e_refeita(isolado):
    data, _ = isolado
    (data / session.KEY_FILE).write_bytes(b"curta")
    assert session.current_key() is None
    k = session.ensure_key()
    assert k is not None and len(k) == session.KEY_LEN


@pytest.mark.skipif(sys.platform == "win32", reason="permissao POSIX")
def test_chave_so_o_dono_le(isolado):
    data, _ = isolado
    session.ensure_key()
    assert stat.S_IMODE(os.stat(data / session.KEY_FILE).st_mode) == 0o600


# --------------------------------------------------------------------------- #
# Filtros aplicados a qualquer lista
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("p", [
    "\\\\host\\share\\a.txt", "//host/share/a.txt",
    "/\\host\\share\\a.txt", "\\/host/share/a.txt",       # misturas que o Windows aceita igual
    "\\\\?\\UNC\\host\\share\\a.txt",
])
def test_caminho_de_rede(p):
    assert session.is_remote(p)


def test_caminho_local_nao_e_rede():
    assert not session.is_remote("C:\\docs\\a.txt")
    assert not session.is_remote("/home/ana/a.txt")


def test_restorable_teto_absoluto_e_sem_rede():
    base = "C:\\d\\" if os.name == "nt" else "/d/"
    lista = [f"{base}{i}.txt" for i in range(60)]
    assert session.restorable(lista) == lista[:session.MAX_RESTORE]
    misturada = [base + "ok.txt", "relativo.txt", "", "//host/s/x.txt", "\\/host/s/x.txt", 42,
                 base + "ok2.txt"]
    assert session.restorable(misturada) == [base + "ok.txt", base + "ok2.txt"]


# --------------------------------------------------------------------------- #
# config: o que vai para as configuracoes e volta
# --------------------------------------------------------------------------- #
def test_config_salva_assinado_e_confere(isolado):
    _, s = isolado
    config.save_session(PATHS, 1)
    assert isinstance(s.value("session/mac"), str) and len(s.value("session/mac")) == 64
    assert config.load_session_checked() == (PATHS, 1, session.OK)


def test_config_lista_editada_por_fora_nao_confere(isolado):
    _, s = isolado
    config.save_session(PATHS, 0)
    s.setValue("session/paths", [*PATHS, "C:\\evil.txt"])   # escrita direta, como no registro
    assert config.load_session_checked()[2] == session.TAMPERED
    s.setValue("session/paths", PATHS)
    s.remove("session/mac")                                  # "apagar a assinatura" nao adianta
    assert config.load_session_checked()[2] == session.TAMPERED
    s.setValue("session/mac", ["tipo", "trocado"])          # tipo trocado = sem assinatura
    assert config.load_session_checked()[2] == session.TAMPERED


def test_config_lista_de_antes_da_assinatura_vale_uma_vez(isolado):
    _, s = isolado
    s.setValue("session/paths", PATHS)                       # como a 1.4.0 gravava: sem mac
    s.setValue("session/active", 0)
    assert config.load_session_checked() == (PATHS, 0, session.LEGACY)
    config.save_session(PATHS, 0)                            # o proximo fechamento ja assina
    assert config.load_session_checked()[2] == session.OK


def test_config_um_so_caminho_confere(isolado):
    """O .ini devolve str quando a lista tem 1 item: a assinatura tem de sobreviver a isso."""
    config.save_session(PATHS[:1], 0)
    assert config.load_session_checked() == (PATHS[:1], 0, session.OK)


def test_config_sem_pasta_de_dados_grava_sem_assinatura(isolado, monkeypatch):
    _, s = isolado
    monkeypatch.setattr(session, "ensure_key", lambda: None)
    config.save_session(PATHS, 0)
    assert s.value("session/mac") is None
    monkeypatch.setattr(session, "current_key", lambda: None)
    assert config.load_session_checked()[2] == session.LEGACY
