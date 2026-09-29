"""Testes da Sentinela de Segredos (notepy/secrets.py) — puro Python, sem Qt."""

import random
import string
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
    # --- provedores adicionados na expansao da Sentinela ---
    ('cred = ASIA3FK7XQ2MNP8RTUVW', "Chave de acesso AWS"),                 # credencial temporaria
    ('-----BEGIN PGP PRIVATE KEY BLOCK-----', "Chave privada PEM"),
    ('-----BEGIN OPENSSH PRIVATE KEY-----', "Chave privada PEM"),
    ('t = github_pat_' + ('aB3' * 28)[:82], "Token fine-grained do GitHub"),
    ('GL = glpat-aB3dEfGh1jKlMn0pQrSt', "Token do GitLab"),
    ('GOOGLE = GOCSPX-abcdefghijklmnopqrstuvwxyz12', "Segredo OAuth do Google"),
    ('bot 123456789:AABCdef0123456789ghijklmnopqrstuvwx', "Token do Telegram"),
    ('AccountKey=' + ('AbC9d2' * 15)[:86] + '==', "Chave de conta Azure Storage"),
    ('SHOP = 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', "Token Shopify"),
    ('DO = dop_v1_' + '0123456789abcdef' * 4, "Token DigitalOcean"),
    ('SQ = sq0atp-aB3dEfGh1jKlMn0pQrStUv', "Token Square"),
    ('PYPI = pypi-AgEI' + ('aB3dEf' * 10), "Token PyPI"),
    ('PM = PMAK-a1b2c3d4e5f6a7b8c9d0e1f2-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7', "Chave Postman"),
    ('VAULT = hvs.aB3dEfGh1jKlMn0pQrStUvWx012345', "Token HashiCorp Vault"),
    ('DP = dp.pt.aB3dEfGh1jKlMn0pQrStUvWxYz0123456789abcd', "Token Doppler"),
]


@pytest.mark.parametrize("text,kind", DETECT)
def test_detecta(text, kind):
    assert kind in kinds(text), f"esperava {kind!r} em {text!r}, veio {kinds(text)}"


# --------------------------------------------------------------------------- #
# Provedores que antes so a entropia pegava (ou que escapavam, como o sbp_ do Supabase).
# Os tokens sao GERADOS aqui (semente fixa): nenhum token inteiro fica escrito no fonte,
# para o proprio repositorio nao carregar algo com cara de credencial.
# --------------------------------------------------------------------------- #
_RNG = random.Random(1505)
_B62 = string.ascii_letters + string.digits
_URL = _B62 + "-_"
_HEX = "0123456789abcdef"


def _t(n, alphabet=_B62):
    return "".join(_RNG.choice(alphabet) for _ in range(n))


NEW_PROVIDERS = [
    ("sk-ant-" + "api03-" + _t(93, _URL) + "AA", "Chave da Anthropic"),
    ("sk-ant-" + "admin01-" + _t(93, _URL) + "AA", "Chave da Anthropic"),
    ("hf_" + _t(34, string.ascii_letters), "Token Hugging Face"),
    ("dckr_" + "pat_" + _t(27, _URL), "Token Docker Hub"),
    ("sntrys_" + "eyJpYXQiOjE3MjY" + _t(80, _B62 + "+/") + "_" + _t(43, _B62 + "+/"), "Token Sentry"),
    ("sntryu_" + _t(64, _HEX), "Token Sentry"),
    ("glsa_" + _t(32) + "_" + _t(8, _HEX), "Token Grafana"),
    ("glc_" + "eyJvIjoiMTIzNCIs" + _t(60, _B62 + "+/") + "==", "Token Grafana"),
    ("lin_" + "api_" + _t(40), "Chave da Linear"),
    ("figd_" + _t(40, _URL), "Token Figma"),
    ("ATATT3" + "xFfGF0" + _t(180, _URL + "=") + "=" + _t(8, _HEX).upper(), "Token Atlassian"),
    ("pscale_" + "tkn_" + _t(43, _URL), "Credencial PlanetScale"),
    ("pscale_" + "pw_" + _t(43, _URL), "Credencial PlanetScale"),
    ("sbp_" + _t(40, _HEX), "Token Supabase"),
    ("sb_" + "secret_" + _t(32, _URL), "Token Supabase"),
    ("ya29." + _t(120, _URL), "Token de acesso OAuth do Google"),
]


@pytest.mark.parametrize("contexto", [
    "API_KEY = \"{}\"",                                   # atribuicao com aspas
    "2026-09-29 10:00:01 INFO auth ok {} user=ana",         # solto numa linha de log
    "curl -H 'X-Token: {}' https://api.local",             # colado de um terminal
])
@pytest.mark.parametrize("token,kind", NEW_PROVIDERS)
def test_provedores_novos_com_rotulo_proprio(token, kind, contexto):
    """Rotulo do PROVEDOR (nao 'alta entropia') e o achado cobre o token inteiro."""
    text = contexto.format(token)
    hits = s.scan(text)
    assert [m.kind for m in hits] == [kind], f"{kind}: {[m.kind for m in hits]}"
    assert hits[0].snippet == token


def test_supabase_hex_nao_escapa_mais():
    """40 hex tem pouca entropia por caractere: a camada 5 sozinha deixava passar."""
    tok = "sbp_" + _t(40, _HEX)
    assert kinds(f"log {tok} fim") == ["Token Supabase"]
    assert s.scan(f"log {tok} fim", entropy=False)            # nao depende da entropia


def test_sas_do_azure_marca_so_a_assinatura():
    sig = _t(43, _B62 + "+/").replace("+", "%2B").replace("/", "%2F") + "%3D"
    url = ("https://conta.blob.core.windows.net/docs/a.pdf?sp=r&st=2026-09-29T10:00:00Z"
           "&se=2026-09-30T10:00:00Z&spr=https&sv=2022-11-02&sr=b&sig=" + sig)
    hits = s.scan(url)
    assert [m.kind for m in hits] == ["Assinatura SAS do Azure"]
    assert hits[0].snippet == sig                              # a URL em volta e publica


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
    'repo = glpat-curtinha',                 # prefixo certo, curto demais (<20)
    'x = GOCSPX-curto',                      # GOCSPX- mas tamanho errado
    'pkg = pypi-test-build-123',             # pypi- mas nao macaroon 'AgEI...'
    'cfg = AccountKey=abc',                  # AccountKey= mas nao base64(86)==
    'result = hvs.interpolate_missing_timestamps(data)',   # 'hvs.' + metodo snake_case (FP corrigido)
    # prefixos dos provedores novos em codigo comum (nao sao credenciais)
    "path = hf_hub_download(repo_id='bert-base', filename='config.json')",
    "k = sk-ant-api03-curta",
    "ya29.curto",
    "loader = sbp_config_loader(opts)",
    "pscale_pw_test = conectar()",
    "url = 'https://example.com/foto.png?w=200&sig=abc123'",   # sig= sem o sv= do Azure
    "usuario = figd_sem_token",
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
