"""Testes do nucleo de codecs (transforms.py) — Python puro, sem Qt."""

import base64

import pytest

from notepy import transforms as T


# --------------------------------------------------------------------------- #
# Round-trips (incl. unicode multibyte)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("enc,dec", [
    (T.b64_encode, T.b64_decode),
    (T.b64url_encode, T.b64url_decode),
    (T.hex_encode, T.hex_decode),
    (T.url_encode, T.url_decode),
    (T.qp_encode, T.qp_decode),
])
@pytest.mark.parametrize("txt", ["", "Man", "café 日本 🚀", "a b/c?d=e&f", "x" * 1000])
def test_roundtrip(enc, dec, txt):
    assert dec(enc(txt)) == txt


# --------------------------------------------------------------------------- #
# Vetores conhecidos
# --------------------------------------------------------------------------- #
def test_vetores_conhecidos():
    assert T.b64_encode("Man") == "TWFu"
    assert T.b64_decode("TWFu") == "Man"
    assert T.hex_encode("AB") == "4142"
    assert T.hex_decode("4142") == "AB"
    assert T.url_encode("a b/c") == "a%20b%2Fc"
    assert T.url_decode("a%20b%2Fc") == "a b/c"
    # base64url sem padding (forma de JWT)
    assert "=" not in T.b64url_encode("qualquer coisa")


def test_hex_decode_ignora_espacos():
    assert T.hex_decode("41 42\n43") == "ABC"


# --------------------------------------------------------------------------- #
# Entrada invalida -> TransformError (nunca crash)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fn,arg", [
    (T.b64_decode, "!!!nao-base64"),
    (T.b64url_decode, "###"),
    (T.hex_decode, "zz"),
    (T.qp_decode, "café="),          # nao-ASCII em QP
])
def test_invalido_levanta_transform_error(fn, arg):
    with pytest.raises(T.TransformError):
        fn(arg)


def test_decode_binario_recusado():
    """Decodar bytes que nao sao UTF-8 nao injeta lixo no editor — vira erro amigavel."""
    blob = base64.b64encode(b"\xff\xfe\x00\x01").decode()
    with pytest.raises(T.TransformError):
        T.b64_decode(blob)
    with pytest.raises(T.TransformError):
        T.hex_decode("fffe0001")


# --------------------------------------------------------------------------- #
# Teto anti-DoS
# --------------------------------------------------------------------------- #
def test_teto_de_tamanho():
    grande = "x" * (T.MAX_INPUT + 1)
    with pytest.raises(T.TransformError):
        T.b64_encode(grande)
    with pytest.raises(T.TransformError):
        T.hex_encode(grande)


@pytest.mark.parametrize("enc", [
    T.b64_encode, T.b64url_encode, T.hex_encode, T.url_encode, T.qp_encode])
@pytest.mark.parametrize("ruim", ["\ud800", "a\ud83d", "\udfff fim"])
def test_encoder_surrogate_vira_transform_error(enc, ruim):
    """Red-team v1.3: surrogate solitario/partido (que o buffer pode conter) NAO pode
    escapar como UnicodeEncodeError — viraria crash no slot Qt. Tem que ser TransformError."""
    with pytest.raises(T.TransformError):
        enc(ruim)


# --------------------------------------------------------------------------- #
# JWT — decodifica header+payload, nao verifica assinatura
# --------------------------------------------------------------------------- #
def _fake_jwt() -> str:
    def part(obj):
        import json
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    h = part({"alg": "HS256", "typ": "JWT"})
    p = part({"sub": "natan", "role": "master"})
    return f"{h}.{p}.assinaturafalsa"


def test_jwt_decode_mostra_header_payload_e_avisa_assinatura():
    out = T.jwt_decode(_fake_jwt())
    assert "HS256" in out and "natan" in out and "master" in out
    assert "NAO verifica" in out                       # honestidade explicita
    assert "presente (NAO verificada)" in out


def test_jwt_sem_assinatura_ok():
    jwt = _fake_jwt().rsplit(".", 1)[0]                 # so header.payload
    out = T.jwt_decode(jwt)
    assert "ausente" in out


@pytest.mark.parametrize("bad", ["", "abc", "naoeumjwt", "a.b.c.d", "@@@.@@@"])
def test_jwt_invalido_levanta(bad):
    with pytest.raises(T.TransformError):
        T.jwt_decode(bad)
