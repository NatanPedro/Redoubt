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


# --------------------------------------------------------------------------- #
# RDBT2 — envelope / key-slots (Cofre++)
# --------------------------------------------------------------------------- #
def test_formato_rdbt2():
    assert vault.encrypt(SECRET, PW)[:5] == b"RDBT2"


def test_multiplas_senhas_independentes():
    o = vault.open_vault(vault.encrypt(SECRET, "senha-A"), password="senha-A")
    slots = vault.add_unlocker(o.key, o.slots, password="senha-B")
    blob = vault.reseal(SECRET, o.key, slots)
    assert vault.decrypt(blob, "senha-A") == SECRET          # 1a senha abre
    assert vault.decrypt(blob, "senha-B") == SECRET          # 2a senha abre o MESMO cofre
    with pytest.raises(vault.WrongPassword):
        vault.decrypt(blob, "senha-C")                       # senha nao-cadastrada nao abre


def test_arquivo_chave():
    kf = b"\x00\x01material-de-arquivo-chave\xff\xfe" * 4
    blob = vault.new_vault(SECRET, keyfile=kf)
    assert vault.decrypt(blob, keyfile=kf) == SECRET
    with pytest.raises(vault.WrongPassword):
        vault.decrypt(blob, keyfile=b"arquivo errado")
    with pytest.raises(vault.WrongPassword):
        vault.decrypt(blob, password="qualquer-senha")       # so keyfile abre


def test_senha_E_keyfile_no_mesmo_cofre():
    kf = b"keyfile-bytes-aqui-1234567890"
    blob = vault.new_vault(SECRET, password=PW, keyfile=kf)
    assert vault.decrypt(blob, password=PW) == SECRET        # senha abre
    assert vault.decrypt(blob, keyfile=kf) == SECRET         # keyfile tambem abre


def test_reseal_preserva_todos_os_destravadores():
    o = vault.open_vault(vault.new_vault("v1", password="A", keyfile=b"KF-bytes-xyz"), password="A")
    novo = vault.reseal("v2 conteudo", o.key, o.slots)
    assert vault.decrypt(novo, password="A") == "v2 conteudo"
    assert vault.decrypt(novo, keyfile=b"KF-bytes-xyz") == "v2 conteudo"   # keyfile sobreviveu


def test_le_e_migra_rdbt1_legado():
    # constroi um blob RDBT1 (formato antigo) na mao e confirma leitura + migracao
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    header = b"RDBT1" + bytes([1, 15, 8, 1]) + salt + nonce
    key = vault._scrypt(PW.encode("utf-8"), salt, 15, 8, 1)
    blob_v1 = header + AESGCM(key).encrypt(nonce, SECRET.encode("utf-8"), header)
    assert blob_v1[:5] == b"RDBT1"
    o = vault.open_vault(blob_v1, password=PW)
    assert o.text == SECRET                                  # le o legado
    novo = vault.reseal(o.text, o.key, o.slots)              # migra p/ RDBT2 ao re-selar
    assert novo[:5] == b"RDBT2" and vault.decrypt(novo, PW) == SECRET


def test_slot_kdf_bomba_bloqueada():
    blob = bytearray(vault.encrypt("x", PW))
    blob[8] = 63                       # log2n do slot 0 (offset 7+1) -> scrypt bomba
    with pytest.raises(vault.VaultError):
        vault.decrypt(bytes(blob), PW)


def test_strip_de_slot_detectado():
    # remove um slot a forca: o conteudo (AAD = todos os slots) deixa de verificar
    o = vault.open_vault(vault.new_vault(SECRET, password="A"), password="A")
    slots2 = vault.add_unlocker(o.key, o.slots, password="B")
    blob = bytearray(vault.reseal(SECRET, o.key, slots2))    # 2 slots
    blob[6] = 1                                              # mente: diz que ha 1 slot
    with pytest.raises(vault.VaultError):                    # truncado/AAD nao confere
        vault.decrypt(bytes(blob), "A")


def test_slot_kinds():
    assert vault.slot_kinds(vault.new_vault("x", password="A")) == [0]
    assert vault.slot_kinds(vault.new_vault("x", keyfile=b"kf-1234")) == [1]
    o = vault.open_vault(vault.new_vault("x", password="A"), password="A")
    blob = vault.reseal("x", o.key, vault.add_unlocker(o.key, o.slots, keyfile=b"kf-1234"))
    assert vault.slot_kinds(blob) == [0, 1]
