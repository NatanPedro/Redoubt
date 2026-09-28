"""Modelo de exibicao da interface — nucleo puro, sem Qt.

O que a interface MOSTRA sobre um segredo e sobre uma senha, decidido aqui para ser testavel:

  - `category(kind)`: a camada da Sentinela que achou o segredo (para os filtros do painel);
  - `mask(snippet)`: a previa mascarada. O painel da Sentinela fica na tela, e a tela e
    exatamente o que se compartilha: a previa mostra so o PREFIXO que identifica o provedor
    (`AKIA`, `ghp_`, `sk_live_`), nunca o fim do segredo, e nada de PII/cartao/senha;
  - `password_strength(pw)`: estimativa HONESTA de entropia para o medidor ao selar um cofre.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass

# Prefixos publicos de provedor: identificam o TIPO da credencial, nao a credencial.
_PUBLIC_PREFIXES = (
    "sk_live_", "sk_test_", "rk_live_", "rk_test_", "github_pat_", "sk-proj-", "pypi-AgEI",
    "dop_v1_", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "glpat-", "GOCSPX-", "PMAK-",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "npm_", "AKIA", "ASIA", "AIza", "hvs.", "sk-",
    "SG.", "eyJ", "shpat_", "shpss_", "shppa_", "shpca_", "sq0atp-", "sq0csp-", "dp.",
)

CATEGORIES = ("credencial", "pii")

# Os rotulos da Sentinela sao ASCII (vao para logs/hook git); na tela, com acento.
_DISPLAY = {
    "Segredo em atribuicao": "Segredo em atribuição",
    "Cartao de credito": "Cartão de crédito",
    "CPF (sem mascara)": "CPF (sem máscara)",
    "CNPJ (sem mascara)": "CNPJ (sem máscara)",
    "Possivel segredo (alta entropia)": "Possível segredo (alta entropia)",
    "segredo registrado": "Segredo da sua lista",
}


def display(kind: str) -> str:
    """Rotulo para exibir (com acentuacao); desconhecido volta como veio."""
    return _DISPLAY.get(kind, kind)


def category(kind: str) -> str:
    """'pii' para dado pessoal (CPF/CNPJ/cartao); 'credencial' para o resto."""
    k = kind.lower()
    if k.startswith(("cpf", "cnpj", "cartao", "cartão")):
        return "pii"
    return "credencial"


def layer(kind: str) -> str:
    """Rotulo curto da camada que detectou (mostrado ao lado do achado)."""
    k = kind.lower()
    if k.startswith(("cpf", "cnpj")):
        return "PII · DV"
    if k.startswith(("cartao", "cartão")):
        return "Luhn"
    if "atribuicao" in k or "atribuição" in k:
        return "chave=valor"
    if "entropia" in k:
        return "entropia"
    if k == "segredo registrado":
        return "sua lista"
    return "provedor"


def mask(snippet: str, kind: str = "") -> str:
    """Previa mascarada, segura para aparecer na tela.

    So credenciais de provedor com prefixo PUBLICO conhecido mostram esse prefixo; todo o
    resto (senha, PII, cartao, entropia, lista do usuario) vira so pontos. Sempre 8 pontos:
    a previa nao entrega nem o comprimento do segredo.
    """
    s = snippet.strip()
    shown = ""
    if category(kind) == "credencial" and layer(kind) == "provedor":
        for p in _PUBLIC_PREFIXES:
            if s.startswith(p) and len(s) >= len(p) + 8:
                shown = p
                break
    return f"{shown}{'•' * 8}"


@dataclass(frozen=True)
class Strength:
    bits: int
    level: int          # 0..4 (nenhuma, fraca, razoavel, boa, forte)
    label: str


_LABELS = ("Vazia", "Fraca", "Razoável", "Boa", "Forte")


def password_strength(pw: str) -> Strength:
    """Entropia estimada pelo tamanho do alfabeto usado x comprimento, com desconto para
    repeticao. E um TETO otimista (nao conhece palavras de dicionario): o medidor diz isso."""
    if not pw:
        return Strength(0, 0, _LABELS[0])
    pool = 0
    if any(c in string.ascii_lowercase for c in pw):
        pool += 26
    if any(c in string.ascii_uppercase for c in pw):
        pool += 26
    if any(c in string.digits for c in pw):
        pool += 10
    if any(c in string.punctuation or c == " " for c in pw):
        pool += 33
    if any(ord(c) > 127 for c in pw):
        pool += 64
    distinct = len(set(pw))
    effective = min(len(pw), distinct * 2)       # "aaaaaaaa" nao vale 8 simbolos
    bits = int(effective * math.log2(max(pool, 2)))
    if bits < 40:
        level = 1
    elif bits < 60:
        level = 2
    elif bits < 80:
        level = 3
    else:
        level = 4
    return Strength(bits, level, _LABELS[level])
