"""Testes da custodia assinada + trilha (notepy/custody.py) — puro Python, sem Qt."""

import json

import pytest

from notepy import custody


@pytest.fixture
def tmp_identity(tmp_path, monkeypatch):
    """Aponta a identidade/trilha p/ um dir temporario (nao toca no APPDATA real)."""
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path))
    return tmp_path


# --------------------------------------------------------------------------- #
# Assinatura
# --------------------------------------------------------------------------- #
def test_sign_verify_roundtrip(tmp_identity):
    sig = custody.sign("conteudo importante")
    assert custody.verify("conteudo importante", sig)


def test_verify_detecta_adulteracao(tmp_identity):
    sig = custody.sign("original")
    assert not custody.verify("original alterado", sig)     # 1 char muda -> falha


def test_verify_com_chave_publica_exportada(tmp_identity):
    sig = custody.sign("x")
    pub = custody.public_key_b64()
    assert custody.verify("x", sig, pub)
    assert not custody.verify("y", sig, pub)


def test_chave_de_outra_instalacao_nao_verifica(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir(); (tmp_path / "b").mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "a"))
    sig = custody.sign("msg"); pub_a = custody.public_key_b64()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "b"))
    pub_b = custody.public_key_b64()
    assert pub_a != pub_b
    assert not custody.verify("msg", sig, pub_b)             # sig de A nao confere com B


def test_chave_persiste_entre_chamadas(tmp_identity):
    assert custody.public_key_b64() == custody.public_key_b64()
    assert len(custody.fingerprint()) == 16


def test_verify_entrada_lixo_nao_crasha(tmp_identity):
    assert custody.verify("x", "nao-e-base64-valido!!!") is False
    assert custody.verify("x", "YWJj", "chave-lixo") is False


# --------------------------------------------------------------------------- #
# Trilha de auditoria encadeada
# --------------------------------------------------------------------------- #
def test_auditoria_encadeada(tmp_identity):
    custody.log_event("abriu", "a.txt", "h1", ts="2026-01-01T00:00:00+00:00")
    custody.log_event("selou", "a.txt", "h2", ts="2026-01-01T00:01:00+00:00")
    e = custody.read_audit()
    assert len(e) == 2
    assert e[1]["prev"] == e[0]["hash"]                     # encadeado
    ok, idx = custody.verify_chain()
    assert ok and idx == -1


def test_auditoria_detecta_adulteracao(tmp_identity):
    custody.log_event("abriu", "a.txt", "h1", ts="2026-01-01T00:00:00+00:00")
    custody.log_event("selou", "a.txt", "h2", ts="2026-01-01T00:01:00+00:00")
    custody.log_event("queimou", "b.txt", "h3", ts="2026-01-01T00:02:00+00:00")
    p = custody._audit_path()
    lines = open(p, encoding="utf-8").read().splitlines()
    bad = json.loads(lines[1]); bad["detail"] = "ADULTERADO"  # mexe num evento passado
    lines[1] = json.dumps(bad, ensure_ascii=False)
    open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    ok, idx = custody.verify_chain()
    assert not ok and idx == 1                              # cadeia quebra na entrada 1


def test_auditoria_vazia(tmp_identity):
    assert custody.read_audit() == []
    assert custody.verify_chain() == (True, -1)
