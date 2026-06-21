"""Testes do Cofre (notepy/vault.py) — AES-256-GCM + scrypt, sem Qt."""

import time

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from notepy import vault


def _x25519_priv(k):
    return k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())


def _x25519_pub(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

PW = "senha-mestra-de-teste"
SECRET = "senha do banco: batata123\nnetflix: lulu2010"


@pytest.fixture(autouse=True)
def _argon_rapido(monkeypatch):
    """Argon2id leve (1 MiB, t=1) para a suite rodar rapido; producao usa 64 MiB / t=3."""
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_MEMLOG2", 10)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_T", 1)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_LANES", 1)


def _build_rdbt2_scrypt(secret: str, password: str, log2n: int = 14) -> bytes:
    """Constroi na mao um cofre RDBT2 legado (slot scrypt) — para testar retrocompatibilidade."""
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ck = vault.generate_key()
    salt, wrap_nonce = os.urandom(16), os.urandom(12)
    kind_byte = vault.KIND_PASSWORD | (vault.KDF_SCRYPT << 4)        # nibble alto 0 = scrypt
    head = bytes([kind_byte, log2n, 8, 1]) + salt + wrap_nonce
    kek = vault._scrypt(password.encode("utf-8", "surrogatepass"), salt, log2n, 8, 1)
    slot = head + AESGCM(kek).encrypt(wrap_nonce, ck, head)
    header = bytes([*vault.MAGIC_V2, vault.VERSION, 1])
    cnonce = os.urandom(12)
    ct = AESGCM(ck).encrypt(cnonce, secret.encode("utf-8", "surrogatepass"), header + slot)
    return header + slot + cnonce + ct


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
def test_formato_rdbt4():
    assert vault.encrypt(SECRET, PW)[:5] == b"RDBT4"


def test_usa_argon2id_por_padrao():
    blob = vault.new_vault("x", password="pw")
    assert (blob[7] >> 4) == vault.KDF_ARGON2        # nibble alto do byte kind do slot 0
    assert (blob[7] & 0x0F) == vault.KIND_PASSWORD


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
    novo = vault.reseal(o.text, o.key, o.slots)              # migra p/ RDBT3 (Argon2id) ao re-selar
    assert novo[:5] == b"RDBT4" and vault.decrypt(novo, PW) == SECRET


def test_slot_kdf_bomba_bloqueada():
    """Argon2id com memory_log2 gigante (2^63 KiB) nao pode travar/derrubar o app."""
    blob = bytearray(vault.encrypt("x", PW))
    blob[11] = 63                      # memory_log2 do slot 0 (RDBT4: 7 hdr + kind + 2 len + t) -> bomba
    t = time.time()
    with pytest.raises(vault.VaultError):
        vault.decrypt(bytes(blob), PW)
    assert time.time() - t < 1.0, "validacao de parametros deveria ser instantanea"


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
    assert vault.slot_kinds(blob) == [0, 1]               # mascarado p/ nibble baixo (ignora KDF)


# --------------------------------------------------------------------------- #
# RDBT3 — Argon2id + retrocompatibilidade scrypt (KDF por slot)
# --------------------------------------------------------------------------- #
def test_rdbt2_scrypt_legado_ainda_abre():
    """Um cofre RDBT2 antigo (slot scrypt) continua abrindo; re-selar migra o envelope p/ RDBT3."""
    blob = _build_rdbt2_scrypt(SECRET, PW)
    assert blob[:5] == b"RDBT2"
    assert vault.decrypt(blob, PW) == SECRET                   # scrypt legado abre
    with pytest.raises(vault.WrongPassword):
        vault.decrypt(blob, "errada")
    o = vault.open_vault(blob, password=PW)
    novo = vault.reseal(o.text, o.key, o.slots)                # re-sela: MAGIC RDBT3, slot scrypt preservado
    assert novo[:5] == b"RDBT4"                                 # re-selar migra o envelope p/ RDBT4
    assert (novo[7] >> 4) == vault.KDF_SCRYPT                   # o slot continua scrypt (nao re-derivavel)
    assert vault.decrypt(novo, PW) == SECRET


def test_mistura_scrypt_e_argon_no_mesmo_cofre():
    """Slot scrypt (legado) + slot Argon2id (novo) abrem o MESMO cofre, cada um com seu KDF."""
    base = _build_rdbt2_scrypt(SECRET, "scrypt-pw")
    o = vault.open_vault(base, password="scrypt-pw")
    slots = vault.add_unlocker(o.key, o.slots, password="argon-pw")   # +slot Argon2id
    novo = vault.reseal(SECRET, o.key, slots)
    assert [s[0] >> 4 for s in slots] == [vault.KDF_SCRYPT, vault.KDF_ARGON2]
    assert vault.decrypt(novo, "scrypt-pw") == SECRET          # slot scrypt (legado) abre
    assert vault.decrypt(novo, "argon-pw") == SECRET           # slot Argon2id (novo) abre
    with pytest.raises(vault.WrongPassword):
        vault.decrypt(novo, "nao-cadastrada")


def test_downgrade_de_kdf_no_slot_detectado():
    """Trocar o KDF no byte kind (argon->scrypt) quebra o GCM do slot (o byte esta na AAD)."""
    blob = bytearray(vault.new_vault(SECRET, password=PW))     # slot Argon2id
    assert (blob[7] >> 4) == vault.KDF_ARGON2
    blob[7] = vault.KIND_PASSWORD | (vault.KDF_SCRYPT << 4)     # forca nibble do KDF p/ scrypt
    with pytest.raises(vault.VaultError):                      # scrypt c/ params de argon + AAD muda -> falha
        vault.decrypt(bytes(blob), PW)


# --------------------------------------------------------------------------- #
# Pos red-team: teto de custo do KDF (anti-DoS) + slot ruim pulado (nao fatal)
# --------------------------------------------------------------------------- #
def test_check_scrypt_rejeita_custo_alto():
    """O pior caso que ANTES passava (log2n=18,r=16,p=16 ~ 512 MiB / dezenas de seg) agora e barrado."""
    with pytest.raises(vault.VaultError):
        vault._check_scrypt(18, 16, 16)
    vault._check_scrypt(15, 8, 1)            # default: nao levanta


def test_check_argon_rejeita_custo_alto():
    with pytest.raises(vault.VaultError):
        vault._check_argon(8, 18, 16)        # mem 256 MiB + lanes 16: fora do teto
    vault._check_argon(3, 16, 4)             # default: nao levanta


def test_agregado_de_kdf_excede_orcamento_recusa_rapido():
    """16 slots no teto aceito por-slot (custo 512 cada) somam > orcamento: open_vault recusa
    ANTES de derivar qualquer KEK — instantaneo, em vez de congelar a UI por minutos."""
    import os
    kind = vault.KIND_PASSWORD | (vault.KDF_ARGON2 << 4)
    slot = bytes([kind, 8, 17, 8]) + os.urandom(76)            # argon t=8,memlog2=17: work=2^20 (passa por-slot)
    blob = bytes([*vault.MAGIC_V3, vault.VERSION, 16]) + slot * 16 + os.urandom(12 + 16)
    t = time.time()
    with pytest.raises(vault.VaultError):                      # 16*2^20 = 2^24 > teto agregado 2^22
        vault.decrypt(blob, "qualquer")
    assert time.time() - t < 1.0, "deveria recusar pelo orcamento agregado, sem derivar"


def test_slot_envenenado_antes_do_real_nao_nega_credencial():
    """Um slot com KDF desconhecido prependido ao slot real NAO pode negar a credencial correta."""
    import os
    o = vault.open_vault(vault.new_vault(SECRET, password="dono"), password="dono")
    poison = vault._frame(vault.KIND_PASSWORD | (3 << 4), os.urandom(79))   # slot RDBT4 c/ KDF=3 desconhecido
    blob = vault.reseal(SECRET, o.key, [poison, o.slots[0]])    # envenenado PRIMEIRO
    assert vault.decrypt(blob, "dono") == SECRET               # pula o slot ruim, abre no real


# --------------------------------------------------------------------------- #
# RDBT4 — X25519 (cifrar-para-destinatario)
# --------------------------------------------------------------------------- #
def test_x25519_roundtrip():
    recip = X25519PrivateKey.generate()
    blob = vault.new_vault(SECRET, recipient=_x25519_pub(recip))
    assert blob[:5] == b"RDBT4"
    assert vault.open_vault(blob, x25519_private=_x25519_priv(recip)).text == SECRET
    assert vault.slot_kinds(blob) == [vault.KIND_X25519]
    assert b"batata" not in blob and SECRET.encode() not in blob   # conteudo cifrado


def test_x25519_chave_errada_nao_abre():
    blob = vault.new_vault(SECRET, recipient=_x25519_pub(X25519PrivateKey.generate()))
    outra = _x25519_priv(X25519PrivateKey.generate())
    with pytest.raises(vault.WrongPassword):
        vault.open_vault(blob, x25519_private=outra)
    with pytest.raises(vault.WrongPassword):
        vault.decrypt(blob, "qualquer-senha")                  # senha nao abre um cofre so-destinatario


def test_x25519_multiplos_destinatarios():
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    o = vault.open_vault(vault.new_vault(SECRET, recipient=_x25519_pub(a)),
                         x25519_private=_x25519_priv(a))
    blob = vault.reseal(SECRET, o.key, vault.add_recipient(o.key, o.slots, _x25519_pub(b)))
    assert vault.open_vault(blob, x25519_private=_x25519_priv(a)).text == SECRET   # 1o destinatario
    assert vault.open_vault(blob, x25519_private=_x25519_priv(b)).text == SECRET   # 2o destinatario
    assert vault.slot_kinds(blob) == [vault.KIND_X25519, vault.KIND_X25519]


def test_x25519_misto_senha_e_destinatario():
    recip = X25519PrivateKey.generate()
    o = vault.open_vault(vault.new_vault(SECRET, password="pw"), password="pw")
    blob = vault.reseal(SECRET, o.key, vault.add_recipient(o.key, o.slots, _x25519_pub(recip)))
    assert vault.decrypt(blob, "pw") == SECRET                 # senha abre
    assert vault.open_vault(blob, x25519_private=_x25519_priv(recip)).text == SECRET  # destinatario abre
    assert sorted(vault.slot_kinds(blob)) == [vault.KIND_PASSWORD, vault.KIND_X25519]


def test_x25519_pubkey_invalida_recusada():
    with pytest.raises(vault.VaultError):
        vault.make_x25519_slot(vault.generate_key(), b"curta-demais")


def test_x25519_conteudo_adulterado_detectado():
    recip = X25519PrivateKey.generate()
    blob = bytearray(vault.new_vault(SECRET, recipient=_x25519_pub(recip)))
    blob[-1] ^= 0x01                                            # adultera o ciphertext do conteudo
    with pytest.raises(vault.WrongPassword):
        vault.open_vault(bytes(blob), x25519_private=_x25519_priv(recip))


# --------------------------------------------------------------------------- #
# Pos red-team: robustez do RDBT4/X25519 (nenhum .rdbt malformado derruba o app)
# --------------------------------------------------------------------------- #
def test_x25519_eph_ordem_baixa_nao_derruba():
    """eph_pub de ordem baixa (all-zero) nao crasha open_vault — vira WrongPassword limpo."""
    recip = X25519PrivateKey.generate()
    blob = bytearray(vault.new_vault(SECRET, recipient=_x25519_pub(recip)))
    blob[10:42] = b"\x00" * 32                                  # zera o eph_pub (offset 7+1+2)
    with pytest.raises(vault.WrongPassword):
        vault.open_vault(bytes(blob), x25519_private=_x25519_priv(recip))


@pytest.mark.parametrize("plen", [49, 68])
def test_slot_payload_curto_nao_derruba(plen):
    """Slot senha RDBT4 com payload curto e PULADO (WrongPassword), nunca IndexError/ValueError."""
    import os
    kind = vault.KIND_PASSWORD | (vault.KDF_ARGON2 << 4)
    slot = bytes([kind]) + plen.to_bytes(2, "big") + os.urandom(plen)
    blob = bytes([*vault.MAGIC_V4, vault.VERSION, 1]) + slot + os.urandom(28)
    with pytest.raises(vault.WrongPassword):
        vault.decrypt(blob, password="x")


def test_poison_curto_antes_do_real_ainda_abre():
    """Um slot curto (poison) ANTES do slot real nao impede abrir no real — pula o ruim."""
    import os
    o = vault.open_vault(vault.new_vault(SECRET, password="dono"), password="dono")
    poison = vault._frame(vault.KIND_PASSWORD | (vault.KDF_ARGON2 << 4), os.urandom(49))
    blob = vault.reseal(SECRET, o.key, [poison, o.slots[0]])
    assert vault.decrypt(blob, "dono") == SECRET
