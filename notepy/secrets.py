"""Sentinela de Segredos — detecta credenciais/segredos no texto.

Tudo roda LOCALMENTE, sem rede. Estrategia em camadas, da maior para a menor
confianca, sempre filtrando placeholders/exemplos para nao "gritar lobo":

  1. Padroes de provedor (AWS, Stripe, JWT, PEM, ...) — alta confianca.
  2. Atribuicao keyword=valor (com OU sem aspas), com porteira de complexidade
     do valor e lista de contextos benignos (csrf, paginacao, ...).
  3. PII brasileira: CPF/CNPJ com e sem mascara, validados pelos digitos.
  4. Cartao de credito (validado por Luhn).
  5. Rede de entropia (Shannon) para tokens genericos desconhecidos.

Endurecido contra um corpus adversarial de red-team (v2).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    start: int      # offset (em caracteres) no texto
    end: int
    kind: str       # rotulo legivel
    snippet: str    # trecho casado


# --------------------------------------------------------------------------- #
# 1. Padroes de provedor (alta confianca)
# --------------------------------------------------------------------------- #
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Chave de acesso AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Token JWT", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]{6,})?")),
    ("Chave privada PEM", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Token do GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Token do Slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Webhook do Slack", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("Chave da OpenAI", re.compile(r"\bsk-proj-[A-Za-z0-9]{20,}\b")),
    ("Chave da OpenAI", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Chave Stripe", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Chave SendGrid", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("Chave Twilio", re.compile(r"\b(?:AC|SK)[0-9a-fA-F]{32}\b")),
    ("Token npm", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Chave Google API", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Credencial Basic Auth", re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}")),
    ("Token Bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*")),
    ("Connection string", re.compile(
        r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?)://"
        r"[^\s'\"]+:[^\s'\"]+@[^\s'\"]+")),
]

# --------------------------------------------------------------------------- #
# 2. Atribuicao keyword = valor (com ou sem aspas)
# --------------------------------------------------------------------------- #
_ASSIGN_RE = re.compile(
    r"(?i)(?P<kw>passwd|password|senha|pwd|secret[_-]?key|client[_-]?secret|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|"
    r"secret|token)\s*[:=]\s*(?P<q>['\"]?)(?P<val>[^\s'\"]{6,})(?P=q)")

# contextos benignos a IGNORAR no padrao de atribuicao (token publico/descartavel)
_BENIGN_CONTEXT = re.compile(r"(?i)(csrf|xsrf|next[_-]?page|page[_-]?token|"
                             r"pagination|continuation|anti[_-]?forgery|requestverification)")

# --------------------------------------------------------------------------- #
# 3/4. PII brasileira + cartao
# --------------------------------------------------------------------------- #
_CPF_MASK = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
_CNPJ_MASK = re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b")
_CPF_BARE = re.compile(r"\b\d{11}\b")
_CNPJ_BARE = re.compile(r"\b\d{14}\b")
_CARD_RE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

# --------------------------------------------------------------------------- #
# 5. Rede de entropia (note: SEM '=' no meio, so como padding final)
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")
_ENTROPY_THRESHOLD = 4.5
# Tokens precedidos por estes contextos sao hashes/recursos publicos, nao segredos.
_ENTROPY_SKIP_CTX = re.compile(r"(?i)(data:|sha(?:256|384|512)-|@sha256:|integrity=)$")

# --------------------------------------------------------------------------- #
# Placeholder / exemplo (filtro global)
# --------------------------------------------------------------------------- #
# Numero maximo de matches por varredura (limita custo e marcacao de indicadores).
MAX_MATCHES = 2000

# Marcadores DEFINITIVOS de template/variavel — nunca sao segredo real.
_TEMPLATE_RE = re.compile(r"\$\{|\$\(|\{\{|%\(|<[A-Za-z0-9_]{2,}>")
# 8+ caracteres identicos seguidos (xxxxxxxx, --------) — placeholder, nao chave.
_REPEAT_RE = re.compile(r"(.)\1{7,}")
# Valores-exemplo conhecidos (comparados por valor INTEIRO, em minusculo).
_EXAMPLE_VALUES = {
    "akiaiosfodnn7example", "your-api-key-here", "changeme", "change-me",
    "placeholder", "redacted", "example", "dummy", "sample", "foobar",
    "todo", "fixme", "lorem", "xxx",
}
_UUID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _valid_cpf(d: str) -> bool:
    if len(d) != 11 or len(set(d)) == 1:
        return False

    def check(slice_: str, factor: int) -> int:
        total = sum(int(ch) * (factor - i) for i, ch in enumerate(slice_))
        r = (total * 10) % 11
        return 0 if r == 10 else r

    return check(d[:9], 10) == int(d[9]) and check(d[:10], 11) == int(d[10])


def _valid_cnpj(d: str) -> bool:
    if len(d) != 14 or len(set(d)) == 1:
        return False
    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    w2 = [6] + w1

    def check(slice_: str, weights: list[int]) -> int:
        r = sum(int(c) * w for c, w in zip(slice_, weights)) % 11
        return 0 if r < 2 else 11 - r

    return check(d[:12], w1) == int(d[12]) and check(d[:13], w2) == int(d[13])


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _is_placeholder(snippet: str) -> bool:
    """Placeholder/exemplo — SEM virar kill-switch por substring.

    So veta quando o trecho e CLARAMENTE de exemplo (template/variavel, repeticao
    longa de caractere, valor-exemplo conhecido, ou frase 'your-...-here'). Um
    segredo REAL que por azar contenha 'dummy' como substring NAO e descartado
    (isso era um bypass: bastava embutir 'dummy'/'xxxx' no segredo para escondê-lo).
    """
    s = snippet.strip()
    low = s.lower()
    if _TEMPLATE_RE.search(s) or _REPEAT_RE.search(s):
        return True
    if low in _EXAMPLE_VALUES:
        return True
    if low.startswith(("your-", "your_", "example-", "sample-", "insert_")):
        return True
    if low.endswith(("-here", "_here", "-example", "-placeholder")):
        return True
    return False


def _looks_like_secret_value(v: str) -> bool:
    """Porteira de complexidade: descarta palavras curtas, prosa e UUIDs."""
    if len(v) < 8 or _UUID_RE.match(v):
        return False
    classes = sum((
        any(c.islower() for c in v),
        any(c.isupper() for c in v),
        any(c.isdigit() for c in v),
        any(not c.isalnum() for c in v),
    ))
    return classes >= 2


def _looks_secretish(tok: str) -> bool:
    has_alpha = any(c.isalpha() for c in tok)
    has_digit = any(c.isdigit() for c in tok)
    if not (has_alpha and has_digit):
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", tok) and len(tok) in (32, 40, 64):
        return False  # md5/sha1/sha256 puro = hash, nao segredo
    return True


def scan(text: str, *, entropy: bool = True) -> list[Match]:
    """Varre o texto e devolve os segredos encontrados, ordenados por posicao.

    Deduplica sobreposicoes com um mapa de cobertura O(n) (bytearray) em vez de
    uma busca linear por match — o que antes tornava a varredura O(n^2) e DoS-avel
    (um arquivo com muitos matches congelava a GUI). Limita o total a MAX_MATCHES.
    """
    out: list[Match] = []
    covered = bytearray(len(text))  # 1 = posicao ja coberta por um match

    def add(start: int, end: int, kind: str) -> None:
        if len(out) >= MAX_MATCHES or start >= end:
            return
        snippet = text[start:end]
        if _is_placeholder(snippet):
            return
        if 1 in covered[start:end]:        # sobrepoe um match anterior
            return
        out.append(Match(start, end, kind, snippet))
        covered[start:end] = b"\x01" * (end - start)

    # 1. Provedores
    for kind, pat in _PATTERNS:
        for m in pat.finditer(text):
            add(m.start(), m.end(), kind)

    # 2. Atribuicoes
    for m in _ASSIGN_RE.finditer(text):
        val = m.group("val")
        before = text[max(0, m.start() - 24):m.start()]
        if _BENIGN_CONTEXT.search(before) or _BENIGN_CONTEXT.search(m.group("kw")):
            continue
        if not _looks_like_secret_value(val):
            continue
        add(m.start("val"), m.end("val"), "Segredo em atribuicao")

    # 3. CPF / CNPJ (mascarado e cru), validados por digito verificador
    for pat, kind, valid in (
        (_CPF_MASK, "CPF", _valid_cpf),
        (_CNPJ_MASK, "CNPJ", _valid_cnpj),
        (_CPF_BARE, "CPF (sem mascara)", _valid_cpf),
        (_CNPJ_BARE, "CNPJ (sem mascara)", _valid_cnpj),
    ):
        for m in pat.finditer(text):
            if valid(re.sub(r"\D", "", m.group())):
                add(m.start(), m.end(), kind)

    # 4. Cartao de credito (comprimento real + IIN valido + Luhn)
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if len(digits) in (13, 14, 15, 16, 19) and digits[0] in "23456" and _luhn_ok(digits):
            add(m.start(), m.end(), "Cartao de credito")

    # 5. Rede de entropia
    if entropy:
        for m in _TOKEN_RE.finditer(text):
            if len(out) >= MAX_MATCHES:
                break
            if 1 in covered[m.start():m.end()]:
                continue
            tok = m.group()
            before = text[max(0, m.start() - 12):m.start()]
            # pula hash SRI (sha256-/384-/512-) que o run absorveu como prefixo
            if _ENTROPY_SKIP_CTX.search(before) or re.match(r"(?i)sha(?:256|384|512)-", tok):
                continue
            if shannon_entropy(tok) >= _ENTROPY_THRESHOLD and _looks_secretish(tok):
                add(m.start(), m.end(), "Possivel segredo (alta entropia)")

    out.sort(key=lambda x: x.start)
    return out
