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
from collections.abc import Iterator
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
    # AKIA = chave permanente; ASIA = credencial temporaria (STS).
    ("Chave de acesso AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Token JWT", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]{6,})?")),
    # cobre RSA/EC/OPENSSH/DSA/ENCRYPTED/PGP (...PRIVATE KEY[ BLOCK]-----).
    ("Chave privada PEM", re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----")),
    ("Token do GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Token fine-grained do GitHub", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{82}\b")),
    ("Token do GitLab", re.compile(r"\bglpat-[0-9A-Za-z_-]{20}\b")),
    ("Token do Slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Webhook do Slack", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("Chave da OpenAI", re.compile(r"\bsk-proj-[A-Za-z0-9]{20,}\b")),
    ("Chave da OpenAI", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Chave Stripe", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Chave SendGrid", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("Chave Twilio", re.compile(r"\b(?:AC|SK)[0-9a-fA-F]{32}\b")),
    ("Token npm", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Chave Google API", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Segredo OAuth do Google", re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{28}\b")),
    # token real do Telegram: a parte apos ':' SEMPRE comeca com "AA" (base64) —
    # exigir isso elimina colisao com "epoch:hash" / "id:ref" genericos.
    ("Token do Telegram", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")),
    ("Chave de conta Azure Storage", re.compile(r"(?i)\bAccountKey=[A-Za-z0-9+/]{86}==")),
    ("Token Shopify", re.compile(r"\bshp(?:at|ss|pa|ca)_[0-9a-fA-F]{32}\b")),
    ("Token DigitalOcean", re.compile(r"\bdop_v1_[0-9a-f]{64}\b")),
    ("Token Square", re.compile(r"\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,}\b")),
    ("Token PyPI", re.compile(r"\bpypi-AgEI[A-Za-z0-9_-]{50,}")),
    ("Chave Postman", re.compile(r"\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b")),
    # token Vault e base64url longo de ALTA entropia; o lookahead exige ao menos
    # 1 digito p/ nao casar identificador snake_case benigno (ex.: hvs.algum_metodo).
    ("Token HashiCorp Vault", re.compile(r"\bhvs\.(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{30,}")),
    ("Token Doppler", re.compile(r"\bdp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,}\b")),
    # Antes so a camada de entropia pegava estes (rotulo generico e sem o prefixo na previa); o
    # sbp_ do Supabase, hexadecimal, tem pouca entropia por caractere e ESCAPAVA de todo.
    # O fim `(?![A-Za-z0-9_-])` substitui o \b quando o alfabeto do token inclui '-'.
    ("Chave da Anthropic", re.compile(r"\bsk-ant-[a-z]{2,6}\d{2}-[A-Za-z0-9_-]{80,}")),
    ("Token Hugging Face", re.compile(r"\bhf_[A-Za-z0-9]{34}\b")),
    ("Token Docker Hub", re.compile(r"\bdckr_(?:pat|oat)_[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])")),
    ("Token Sentry", re.compile(r"\bsntrys_eyJ[A-Za-z0-9+/=_-]{50,}|\bsntryu_[0-9a-f]{64}\b")),
    ("Token Grafana", re.compile(r"\bglsa_[A-Za-z0-9]{32}_[0-9a-fA-F]{8}\b|\bglc_eyJ[A-Za-z0-9+/]{30,}={0,2}")),
    ("Chave da Linear", re.compile(r"\blin_api_[A-Za-z0-9]{40}\b|\blin_oauth_[0-9a-f]{64}\b")),
    ("Token Figma", re.compile(r"\bfigd_[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])")),
    ("Token Atlassian", re.compile(r"\bATATT3[A-Za-z0-9_=-]{150,}(?![A-Za-z0-9_=-])")),
    ("Credencial PlanetScale", re.compile(
        r"\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_=.-]{32,64}(?![A-Za-z0-9_=.-])")),
    ("Token Supabase", re.compile(r"\bsbp_[0-9a-f]{40}\b|\bsb_secret_[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])")),
    ("Token de acesso OAuth do Google", re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}(?![0-9A-Za-z_-])")),
    # SAS do Azure: so a ASSINATURA e segredo (o resto da URL e publico). Exige o `sv=AAAA-MM-DD`
    # da mesma query antes do `sig=`, para nao casar qualquer `sig=` da web; o grupo `secret`
    # diz ao scan() que o achado e SO o valor.
    ("Assinatura SAS do Azure", re.compile(
        r"\bsv=\d{4}-\d{2}-\d{2}(?:&[^\s\"'<>&]*)*?&sig=(?P<secret>[A-Za-z0-9%+/=]{40,})")),
    ("Credencial Basic Auth", re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}")),
    ("Token Bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*")),
    ("Connection string", re.compile(
        r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?)://"
        r"[^\s'\"]+:[^\s'\"]+@[^\s'\"]+")),
]

# Prefiltro da camada 1: um padrao so pode casar se ao menos UM destes trechos fixos estiver no
# texto, e procurar trecho fixo (`in`, em C) custa quase nada perto de uma regex que percorre o
# texto todo. Em codigo comum quase nenhum prefixo aparece, entao a maioria das ~40 regex nem
# roda: a varredura fica ~3x mais rapida SEM mudar o resultado (os testes comparam com a
# varredura sem prefiltro e conferem que o trecho esta em todo achado). Padrao (?i) compara com o
# texto em casefold, e o trecho vai em minusculo. Todo rotulo de _PATTERNS PRECISA estar aqui:
# esquecer um e KeyError no import, de proposito.
_LITERALS: dict[str, tuple[str, ...]] = {
    "Chave de acesso AWS": ("AKIA", "ASIA"),
    "Token JWT": ("eyJ",),
    "Chave privada PEM": ("-----BEGIN ",),
    "Token do GitHub": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "Token fine-grained do GitHub": ("github_pat_",),
    "Token do GitLab": ("glpat-",),
    "Token do Slack": ("xox",),
    "Webhook do Slack": ("hooks.slack.com/services/",),
    "Chave da OpenAI": ("sk-",),                    # vale para sk- e sk-proj-
    "Chave Stripe": ("k_live_", "k_test_"),
    "Chave SendGrid": ("SG.",),
    "Chave Twilio": ("AC", "SK"),
    "Token npm": ("npm_",),
    "Chave Google API": ("AIza",),
    "Segredo OAuth do Google": ("GOCSPX-",),
    "Token do Telegram": (":AA",),
    "Chave de conta Azure Storage": ("accountkey=",),
    "Token Shopify": ("shp",),
    "Token DigitalOcean": ("dop_v1_",),
    "Token Square": ("sq0",),
    "Token PyPI": ("pypi-AgEI",),
    "Chave Postman": ("PMAK-",),
    "Token HashiCorp Vault": ("hvs.",),
    "Token Doppler": ("dp.",),
    "Credencial Basic Auth": ("basic",),
    "Token Bearer": ("bearer",),
    "Connection string": ("://",),
    "Chave da Anthropic": ("sk-ant-",),
    "Token Hugging Face": ("hf_",),
    "Token Docker Hub": ("dckr_",),
    "Token Sentry": ("sntrys_", "sntryu_"),
    "Token Grafana": ("glsa_", "glc_"),
    "Chave da Linear": ("lin_",),
    "Token Figma": ("figd_",),
    "Token Atlassian": ("ATATT3",),
    "Credencial PlanetScale": ("pscale_",),
    "Token Supabase": ("sbp_", "sb_secret_"),
    "Token de acesso OAuth do Google": ("ya29.",),
    "Assinatura SAS do Azure": ("&sig=",),
}
# (rotulo, regex, trechos fixos, compara em casefold?)
_PROVIDERS: list[tuple[str, re.Pattern, tuple[str, ...], bool]] = [
    (kind, pat, _LITERALS[kind], bool(pat.flags & re.IGNORECASE)) for kind, pat in _PATTERNS]
_PREFILTER = True                  # os testes desligam para provar que o resultado e o mesmo

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
    w2 = [6, *w1]

    def check(slice_: str, weights: list[int]) -> int:
        # strict=True: os comprimentos batem por construcao (12/12 e 13/13, com len(d)==14
        # garantido acima); se alguem editar os pesos errado, queremos o erro, nao um DV silencioso.
        r = sum(int(c) * w for c, w in zip(slice_, weights, strict=True)) % 11
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

    NOTA (limitacao conhecida, pentest v0.6): um token que contenha 8+ caracteres
    IDENTICOS seguidos (ex.: 'AKIAXXXXXXXXXXXXXXXX', 'ghp_aaaaaaaa…') e tratado
    como placeholder via _REPEAT_RE. Isso veta corretamente exemplos/placeholders
    (o caso comum); o custo e nao detectar um token REAL degenerado com essa forma
    — estatisticamente improvavel num token aleatorio real. Trade-off a favor da
    precisao (manter este filtro evita falsos-positivos em 'XXXX...'/'${...}').
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

    # 1. Provedores (padrao com grupo `secret`: o achado e so esse trecho, nao o contexto)
    folded: str | None = None
    for kind, pat, literals, icase in _PROVIDERS:
        if _PREFILTER:
            if icase:
                if folded is None:
                    folded = text.casefold()
                hay = folded
            else:
                hay = text
            if not any(lit in hay for lit in literals):
                continue                    # sem o trecho fixo, esta regex nao tem como casar
        grp = "secret" if "secret" in pat.groupindex else 0
        for m in pat.finditer(text):
            add(m.start(grp), m.end(grp), kind)

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


# --------------------------------------------------------------------------- #
# Texto grande: varredura em janelas sobrepostas
# --------------------------------------------------------------------------- #
WINDOW_OVERLAP = 4_096      # maior que qualquer credencial: nada se perde na emenda


def iter_windows(text: str, window: int, overlap: int = WINDOW_OVERLAP
                 ) -> Iterator[tuple[int, list[Match]]]:
    """scan() do texto inteiro, uma janela por vez: devolve (ate_onde_ja_foi, achados_da_janela).

    Cada janela "e dona" de [s, s + window) e enxerga `overlap` a mais dos dois lados: um achado
    que comeca na parte dela aparece INTEIRO e com o contexto de antes (atribuicao, SRI...), e o
    que comeca fora fica para a vizinha, que o ve inteiro. Offsets absolutos, em ordem. Quem
    consome decide o ritmo (o hook vai de uma vez; o editor fatia entre eventos da interface) e
    pode parar no meio. Cada janela respeita MAX_MATCHES; o total fica com quem consome."""
    n = len(text)
    if n == 0:
        yield 0, []
        return
    for s in range(0, n, window):
        lo = max(0, s - overlap)
        owned = []
        for m in scan(text[lo:s + window + overlap]):
            a = lo + m.start
            if s <= a < s + window:
                owned.append(Match(a, lo + m.end, m.kind, m.snippet))
        yield min(s + window, n), owned
