"""Transformacoes de texto (codificar/decodificar) — nucleo puro, sem Qt.

MIME Tools + Converter no estilo Notepad++, mas local e auditavel: Base64
(padrao e URL-safe), Hexadecimal, URL (percent), Quoted-printable e o decode
de JWT (header + payload). Cada funcao publica e `str -> str` e levanta
`TransformError` (mensagem amigavel) em entrada invalida ou grande demais —
nunca uma excecao crua que derrube a UI.

Decisoes de seguranca:
- **Teto anti-DoS** (`MAX_INPUT`) checado ANTES de processar: hex dobra o
  tamanho e base64 cresce ~33%, entao recusamos entradas absurdas para nao
  travar a janela nem estourar memoria.
- **Decode recusa binario**: se os bytes decodificados nao forem texto UTF-8,
  levantamos `TransformError` em vez de injetar bytes de controle/mojibake no
  editor.
- **JWT**: apenas DECODIFICA (base64url de header/payload); NAO verifica a
  assinatura — e o chamador deixa isso explicito.
"""

from __future__ import annotations

import base64
import binascii
import json
import quopri
import urllib.parse

# Teto de entrada (caracteres). Alinhado ao limite de varredura do editor (2 MB).
MAX_INPUT = 2 * 1024 * 1024


class TransformError(Exception):
    """Erro amigavel de codificacao/decodificacao (entrada invalida/grande)."""


def _check_size(text: str) -> None:
    if len(text) > MAX_INPUT:
        raise TransformError(
            f"Texto grande demais ({len(text)} caracteres; limite {MAX_INPUT}).")


def _utf8(text: str) -> bytes:
    """Texto -> bytes UTF-8. Surrogate solitario/partido (que o buffer pode conter)
    vira TransformError, em vez de UnicodeEncodeError cru — que escaparia do
    `except TransformError` da UI e derrubaria a janela (red-team v1.3)."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise TransformError(
            "Texto contem caractere invalido (substituto Unicode solitario).") from exc


def _to_text(raw: bytes) -> str:
    """Bytes decodificados -> texto. Recusa binario para nao poluir o editor."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransformError(
            "Decodificado, mas o resultado nao e texto UTF-8 (conteudo binario?).") from exc


# Alfabeto URL-safe -> padrao, para decodar com validate=True (ESTRITO: caractere
# fora do alfabeto vira erro, em vez de ser descartado silenciosamente).
_URL_TO_STD = str.maketrans("-_", "+/")


def _b64url_bytes(chunk: str) -> bytes:
    """Decodifica base64url ESTRITO (repondo o padding). Levanta binascii.Error/ValueError."""
    s = chunk.strip()
    s += "=" * ((-len(s)) % 4)
    return base64.b64decode(s.translate(_URL_TO_STD), validate=True)


# --------------------------------------------------------------------------- #
# Base64 (padrao)
# --------------------------------------------------------------------------- #
def b64_encode(text: str) -> str:
    _check_size(text)
    return base64.b64encode(_utf8(text)).decode("ascii")


def b64_decode(text: str) -> str:
    _check_size(text)
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TransformError("Base64 invalido.") from exc
    return _to_text(raw)


# --------------------------------------------------------------------------- #
# Base64 URL-safe (sem padding, como em JWT / tokens)
# --------------------------------------------------------------------------- #
def b64url_encode(text: str) -> str:
    _check_size(text)
    return base64.urlsafe_b64encode(_utf8(text)).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> str:
    _check_size(text)
    try:
        raw = _b64url_bytes(text)
    except (binascii.Error, ValueError) as exc:
        raise TransformError("Base64 URL invalido.") from exc
    return _to_text(raw)


# --------------------------------------------------------------------------- #
# Hexadecimal (Converter do Notepad++)
# --------------------------------------------------------------------------- #
def hex_encode(text: str) -> str:
    _check_size(text)
    return _utf8(text).hex()


def hex_decode(text: str) -> str:
    _check_size(text)
    s = "".join(text.split())   # ignora espacos/quebras de linha entre os bytes
    try:
        raw = bytes.fromhex(s)
    except ValueError as exc:
        raise TransformError("Hexadecimal invalido.") from exc
    return _to_text(raw)


# --------------------------------------------------------------------------- #
# URL (percent-encoding)
# --------------------------------------------------------------------------- #
def url_encode(text: str) -> str:
    _check_size(text)
    # quote aceita bytes e percent-encoda cada byte; passando _utf8(text) roteamos
    # o erro de surrogate pelo TransformError (quote(str) levantaria UnicodeEncodeError).
    return urllib.parse.quote(_utf8(text), safe="")


def url_decode(text: str) -> str:
    _check_size(text)
    try:
        return urllib.parse.unquote(text, errors="strict")
    except UnicodeDecodeError as exc:
        raise TransformError("URL invalida (os bytes percent nao sao UTF-8).") from exc


# --------------------------------------------------------------------------- #
# Quoted-printable
# --------------------------------------------------------------------------- #
def qp_encode(text: str) -> str:
    _check_size(text)
    return quopri.encodestring(_utf8(text)).decode("ascii")


def qp_decode(text: str) -> str:
    _check_size(text)
    try:
        raw = quopri.decodestring(text.encode("ascii"))
    except UnicodeEncodeError as exc:
        raise TransformError("Quoted-printable invalido (esperado ASCII).") from exc
    return _to_text(raw)


# --------------------------------------------------------------------------- #
# JWT — apenas decodifica (NAO verifica a assinatura)
# --------------------------------------------------------------------------- #
def jwt_decode(text: str) -> str:
    _check_size(text)
    parts = text.strip().split(".")
    if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
        raise TransformError(
            "Nao parece um JWT (esperado header.payload[.assinatura]).")

    def _segment(name: str, chunk: str) -> str:
        try:
            raw = _b64url_bytes(chunk)
        except (binascii.Error, ValueError) as exc:
            raise TransformError(f"{name} do JWT nao e base64url valido.") from exc
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransformError(f"{name} do JWT nao e JSON valido.") from exc
        return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True)

    header = _segment("Header", parts[0])
    payload = _segment("Payload", parts[1])
    has_sig = len(parts) == 3 and bool(parts[2])
    sig = "presente (NAO verificada)" if has_sig else "ausente"
    return (
        f"// Header\n{header}\n\n"
        f"// Payload\n{payload}\n\n"
        f"// Assinatura: {sig}\n"
        f"// O Redoubt apenas DECODIFICA o JWT — nao verifica a assinatura."
    )
