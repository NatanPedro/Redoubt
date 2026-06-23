"""Gerador de senha/passphrase — nucleo puro, sem Qt.

Usa o modulo `secrets` (CSPRNG do SO), NUNCA `random` (que e previsivel). A
senha aleatoria evita caracteres ambiguos (0/O, 1/l/I) e garante ao menos um de
cada classe escolhida. A passphrase sorteia palavras de uma lista embutida; a
entropia e calculada e exibida honestamente (mais palavras = mais forte).
"""

from __future__ import annotations

import math
import secrets

# Alfabetos SEM caracteres ambiguos (legiveis ao digitar/ditar).
_LOWER = "abcdefghijkmnpqrstuvwxyz"      # sem 'l', 'o'
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"      # sem 'I', 'O'
_DIGITS = "23456789"                     # sem '0', '1'
_SYMBOLS = "!@#$%&*-_=+?"

# Lista de palavras curtas e comuns (ASCII) para passphrase. Deduplicada em
# tempo de import; a entropia usa len(WORDS) real (nao um numero presumido).
_RAW_WORDS = (
    "able acid acre aged airy ajar amber anvil apex apple arch arm army atom "
    "aunt aura auto away axis bake bald bare barn base bath bean bear beef bell "
    "belt bend best bird bite blue boat bold bone book boot born boss both bowl "
    "brave brick broom brush cabin cake calm cape card cargo cave cedar cell "
    "chair chalk charm chess chief clay cliff cloak clock cloud coal coast coin "
    "cold colt comet coral cork corn cove crane crisp crop crow crown cube curl "
    "dawn deer desk dial dice dock dome door dove drum dune dusk eagle earth "
    "ember envy fable fairy fang farm fern field film fist flag flame flask "
    "fleet flint float flute foam fork fort fox frog frost fruit gate gem ghost "
    "giant glade glass globe glow goat gold gong grain grape grass grove gulf "
    "hail hand harp hawk hazel heart helm herb hill hive holly honey hook horn "
    "ivory jade jar jet jewel joke joy keel kelp kite knot lace lake lamp lance "
    "leaf lemon lens lily lime lion loft logic lotus lunar lung lyre maple "
    "marble mask maze meadow medal mint mist moon moss moth mound mug myth nest "
    "noble north oak oasis ocean olive onyx opal orbit otter owl palm panda "
    "pearl pine plum pond pony quartz quill quiet raft rain raven reef rice ridge "
    "river robin rock rose ruby sage sail salt sand seal shore silk slate snow "
    "spark spruce stone storm swan thorn tide tiger torch trail tulip vault vine "
    "violet vivid wave whale wheat willow wolf wren yarn zinc"
)
WORDS: tuple[str, ...] = tuple(dict.fromkeys(_RAW_WORDS.split()))

MIN_LEN, MAX_LEN = 8, 128
MIN_WORDS, MAX_WORDS = 3, 12


def gen_password(length: int = 20, use_symbols: bool = True) -> str:
    """Senha aleatoria com >=1 minuscula, maiuscula, digito (e simbolo, se pedido)."""
    length = max(MIN_LEN, min(MAX_LEN, int(length)))
    pools = [_LOWER, _UPPER, _DIGITS]
    if use_symbols:
        pools.append(_SYMBOLS)
    alphabet = "".join(pools)
    chars = [secrets.choice(p) for p in pools]                      # 1 de cada classe
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    # Embaralhamento Fisher-Yates com CSPRNG (nao usar random.shuffle).
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def gen_passphrase(words: int = 6, sep: str = "-") -> str:
    words = max(MIN_WORDS, min(MAX_WORDS, int(words)))
    return sep.join(secrets.choice(WORDS) for _ in range(words))


def password_bits(length: int, use_symbols: bool) -> float:
    length = max(MIN_LEN, min(MAX_LEN, int(length)))
    size = len(_LOWER) + len(_UPPER) + len(_DIGITS) + (len(_SYMBOLS) if use_symbols else 0)
    return round(length * math.log2(size), 1)


def passphrase_bits(words: int) -> float:
    words = max(MIN_WORDS, min(MAX_WORDS, int(words)))
    return round(words * math.log2(len(WORDS)), 1)
