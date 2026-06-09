"""Testes da Sentinela de Segredos (notepy/secrets.py) — puro Python, sem Qt."""

import time

import pytest

from notepy import secrets as s


def kinds(text):
    return sorted({m.kind for m in s.scan(text)})


# --------------------------------------------------------------------------- #
# Deve DETECTAR (verdadeiros-positivos)
# --------------------------------------------------------------------------- #
DETECT = [
    ('key = AKIA3FK7XQ2MNP8RTUVW', "Chave de acesso AWS"),
    ('-----BEGIN RSA PRIVATE KEY-----', "Chave privada PEM"),
    ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4f', "Token JWT"),
    ('ghp_' + 'aB3dEfGh1jKlMn0pQrStUvWxYz2345678901', "Token do GitHub"),
    ('STRIPE = "sk_live_51HCk2pLfAkLmNoPqRsTuVwXy"', "Chave Stripe"),
    ('postgres://admin:S3nh4Sup3r@db.local:5432/prod', "Connection string"),
    ('password = "hunter2secret"', "Segredo em atribuicao"),
    ('DB_PASSWORD = Pg_S3nh4_Forte_2024', "Segredo em atribuicao"),   # SEM aspas
    ('doc 111.444.777-35 aqui', "CPF"),
    ('cpf_cliente = "52998224725"', "CPF (sem mascara)"),
    ('emp 11.222.333/0001-81 ok', "CNPJ"),
    ('cartao = "4111 1111 1111 1111"', "Cartao de credito"),
]


@pytest.mark.parametrize("text,kind", DETECT)
def test_detecta(text, kind):
    assert kind in kinds(text), f"esperava {kind!r} em {text!r}, veio {kinds(text)}"


# --------------------------------------------------------------------------- #
# NAO deve detectar (falsos-positivos / placeholders)
# --------------------------------------------------------------------------- #
NO_DETECT = [
    "O rato roeu a roupa do rei de Roma.",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # git sha1
    "123.456.789-00",                                                    # CPF DV invalido
    "111.111.111-11",                                                    # CPF sequencia
    "def soma(a, b):\n    return a + b",
    'uuid = "550e8400-e29b-41d4-a716-446655440000"',
    'AWS = "AKIAIOSFODNN7EXAMPLE"',          # placeholder canonico AWS
    'api_key = "your-api-key-here"',         # placeholder
    'redis://${USER}:${PASS}@host:6379/0',   # template (${...})
    'k = "AKIAXXXXXXXXXXXXXXXX"',            # repeticao (8+ iguais)
    'numero = "4111 1111 1111 1112"',        # cartao Luhn INVALIDO
]


@pytest.mark.parametrize("text", NO_DETECT)
def test_nao_detecta(text):
    assert kinds(text) == [], f"falso-positivo em {text!r}: {kinds(text)}"


# --------------------------------------------------------------------------- #
# Regressao: bypass "placeholder-poison" (substring de marcador no segredo real)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    'api_key = "AK1x7QdummyP0RtZ9KqWeRtY"',   # contem "dummy"
    'token = "ab12xxxxCd34Ef56Gh"',           # contem "xxxx" (so 4)
    'secret = "todoXY9aB3cD7eFgH1jK"',        # contem "todo"
])
def test_poison_nao_esconde_segredo(text):
    assert kinds(text), f"poison escondeu segredo real: {text!r}"


# --------------------------------------------------------------------------- #
# Validadores diretos
# --------------------------------------------------------------------------- #
def test_valida_cpf():
    assert s._valid_cpf("11144477735")
    assert s._valid_cpf("52998224725")
    assert not s._valid_cpf("12345678900")
    assert not s._valid_cpf("11111111111")


def test_valida_cnpj():
    assert s._valid_cnpj("11222333000181")
    assert not s._valid_cnpj("11222333000199")


def test_luhn():
    assert s._luhn_ok("4111111111111111")
    assert not s._luhn_ok("4111111111111112")


def test_entropia():
    assert s.shannon_entropy("aaaa") == pytest.approx(0.0, abs=1e-9)
    assert s.shannon_entropy("aB3xK9mP2qR7sT1vW5yZ8cD4eF6gH0jL") > 4.5


def test_hash_puro_nao_e_segredo():
    # md5/sha1/sha256 puros (32/40/64 hex) sao excluidos
    assert kinds("d41d8cd98f00b204e9800998ecf8427e") == []          # md5 (32)
    assert kinds("da39a3ee5e6b4b0d3255bfef95601890afd80709") == []  # sha1 (40)


# --------------------------------------------------------------------------- #
# Regressao de DoS: muitos matches -> rapido e CAPADO em MAX_MATCHES
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_dos_capado_e_rapido():
    tok = "aB3xZ9qW7eR2tY5uI8oP1aS4dF6gH0jK"
    text = "\n".join(tok + str(i).zfill(8) for i in range(46000))   # ~1.8MB
    t = time.time()
    out = s.scan(text)
    dt = time.time() - t
    assert len(out) <= s.MAX_MATCHES, "scan nao respeitou o teto de matches"
    assert dt < 5.0, f"scan demorou {dt:.1f}s (DoS O(n^2) pode ter voltado)"
