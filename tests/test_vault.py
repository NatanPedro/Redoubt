"""Testes do Cofre (notepy/vault.py) — AES-256-GCM + scrypt, sem Qt."""

import time

import pytest

from notepy import vault

PW = "senha-mestra-de-teste"
SECRET = "senha do banco: batata123\nnetflix: lulu2010"


def test_round_trip():
    blob = vault.encrypt(SECRET, PW)
    assert vault.looks_like_vault(blob)
    assert vault.decrypt(blob, PW) == SECRET


def test_disco_nao_tem_plaintext():
    blob = vault.encrypt(SECRET, PW)
    assert b"batata" not in blob and b"lulu" not in blob


def test_senha_errada():
    blob = vault.encrypt(SECRET, PW)
    with pytest.raises(vault.WrongPassword):
        vault.decrypt(blob, "senha-errada")


@pytest.mark.parametrize("pos", [50, 12, 30])   # ciphertext, salt, nonce
def test_adulteracao_detectada(pos):
    blob = bytearray(vault.encrypt(SECRET, PW))
    blob[pos] ^= 0x01
    with pytest.raises((vault.WrongPassword, vault.VaultError)):
        vault.decrypt(bytes(blob), PW)


def test_nao_e_cofre():
    with pytest.raises(vault.NotAVault):
        vault.decrypt(b"isto e texto comum, nao um cofre", PW)


def test_scrypt_bomb_bloqueada():
    """Um .rdbt com log2n gigante nao pode travar/derrubar o app."""
    blob = bytearray(vault.encrypt("x", PW))
    blob[6] = 63                       # log2n = 63 -> scrypt alocaria petabytes
    t = time.time()
    with pytest.raises(vault.VaultError):
        vault.decrypt(bytes(blob), PW)
    assert time.time() - t < 1.0, "validacao de parametros deveria ser instantanea"


def test_unicode_e_surrogate():
    txt = "acentuacao 日本語 \U0001F512 \ud83d cauda"
    assert vault.decrypt(vault.encrypt(txt, PW), PW) == txt


def test_vazio():
    assert vault.decrypt(vault.encrypt("", PW), PW) == ""


def test_salt_aleatorio():
    assert vault.encrypt(SECRET, PW) != vault.encrypt(SECRET, PW)


def test_senha_vazia_recusada():
    with pytest.raises(vault.VaultError):
        vault.encrypt("x", "")
