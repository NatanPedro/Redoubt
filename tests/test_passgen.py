"""Testes do gerador de senha/passphrase (passgen.py) — Python puro, sem Qt."""

from notepy import passgen as PG


def test_senha_classes_tamanho_e_sem_ambiguos():
    for _ in range(50):
        s = PG.gen_password(20, use_symbols=True)
        assert len(s) == 20
        assert any(c.islower() for c in s)
        assert any(c.isupper() for c in s)
        assert any(c.isdigit() for c in s)
        assert any(c in PG._SYMBOLS for c in s)
        # nada de caracteres ambiguos
        assert not (set("0O1lI") & set(s))


def test_senha_sem_simbolos():
    for _ in range(20):
        s = PG.gen_password(16, use_symbols=False)
        assert len(s) == 16
        assert not any(c in PG._SYMBOLS for c in s)


def test_tamanho_clampeado():
    assert len(PG.gen_password(1)) == PG.MIN_LEN          # abaixo do minimo -> minimo
    assert len(PG.gen_password(9999)) == PG.MAX_LEN       # acima do maximo -> maximo


def test_passphrase_palavras_da_lista():
    parts = PG.gen_passphrase(6).split("-")
    assert len(parts) == 6
    assert all(w in PG.WORDS for w in parts)


def test_passphrase_clamp():
    assert len(PG.gen_passphrase(1).split("-")) == PG.MIN_WORDS
    assert len(PG.gen_passphrase(99).split("-")) == PG.MAX_WORDS


def test_csprng_nao_repete():
    assert PG.gen_password(24) != PG.gen_password(24)
    assert PG.gen_passphrase(6) != PG.gen_passphrase(6)


def test_entropia_coerente():
    assert PG.password_bits(20, True) > PG.password_bits(20, False)
    assert PG.passphrase_bits(8) > PG.passphrase_bits(4)


def test_wordlist_sem_duplicatas_e_decente():
    assert len(PG.WORDS) == len(set(PG.WORDS))
    assert len(PG.WORDS) >= 100
