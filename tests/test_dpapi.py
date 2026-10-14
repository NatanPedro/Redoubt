"""Destravador "esta conta do Windows" (DPAPI): o cofre (com um DPAPI simulado, em qualquer sistema),
a identidade que abre sem senha nesta conta, e o DPAPI real (so no Windows).

O simulado imita o essencial do real: so a "conta" que protegeu abre, a entropia tem de bater e
qualquer byte trocado falha. Trocar a conta (`conta.trocar()`) simula outra maquina, ou a senha do
Windows redefinida por um administrador."""

import hashlib
import sys

import pytest

from notepy import custody, dpapi, vault

so_windows = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI real so existe no Windows")


class ContaFalsa:
    def __init__(self):
        self.segredo = b"conta-1"

    def trocar(self):
        self.segredo = b"outra-conta"

    def _fluxo(self, n, entropy):
        bloco, i = b"", 0
        while len(bloco) < n:
            bloco += hashlib.sha256(self.segredo + entropy + bytes([i])).digest()
            i += 1
        return bloco[:n]

    def protect(self, data, entropy):
        cifra = bytes(a ^ b for a, b in zip(data, self._fluxo(len(data), entropy), strict=True))
        return b"DPAPI" + hashlib.sha256(self.segredo + entropy + cifra).digest()[:8] + cifra

    def unprotect(self, blob, entropy):
        if not blob.startswith(b"DPAPI"):
            raise OSError("nao e um blob")
        tag, cifra = blob[5:13], blob[13:]
        if hashlib.sha256(self.segredo + entropy + cifra).digest()[:8] != tag:
            raise OSError("outra conta, outra entropia ou blob adulterado")
        return bytes(a ^ b for a, b in zip(cifra, self._fluxo(len(cifra), entropy), strict=True))


@pytest.fixture
def conta(monkeypatch):
    c = ContaFalsa()
    monkeypatch.setattr(dpapi, "available", lambda: True)
    monkeypatch.setattr(dpapi, "protect", c.protect)
    monkeypatch.setattr(dpapi, "unprotect", c.unprotect)
    return c


@pytest.fixture(autouse=True)
def _rapido(monkeypatch):
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_MEMLOG2", 10)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_T", 1)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_LANES", 1)
    custody.lock_identity()
    yield
    custody.lock_identity()


@pytest.fixture
def ident(tmp_path, monkeypatch):
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path))
    custody.sign("x")                                        # cria a identidade (em claro)
    return tmp_path


# --------------------------------------------------------------------------- #
# Cofre
# --------------------------------------------------------------------------- #
def test_cofre_abre_pela_conta_e_so_por_ela():
    c = ContaFalsa()
    blob = vault.new_vault("segredo", dpapi_protect=c.protect)
    assert vault.slot_kinds(blob) == [vault.KIND_DPAPI]
    assert vault.open_vault(blob, dpapi_unprotect=c.unprotect).text == "segredo"
    c.trocar()
    with pytest.raises(vault.WrongPassword):
        vault.open_vault(blob, dpapi_unprotect=c.unprotect)   # outra conta: o slot e pulado


def test_dpapi_convive_com_a_senha_e_e_ignorado_sem_dpapi():
    c = ContaFalsa()
    blob = vault.new_vault("segredo", password="pw", dpapi_protect=c.protect)
    assert vault.slot_kinds(blob) == [vault.KIND_PASSWORD, vault.KIND_DPAPI]
    assert vault.decrypt(blob, password="pw") == "segredo"          # sem DPAPI (ex.: Linux)
    assert vault.open_vault(blob, dpapi_unprotect=c.unprotect).slot_index == 1


def test_slot_dpapi_adulterado_nao_abre():
    c = ContaFalsa()
    blob = bytearray(vault.new_vault("segredo", password="pw", dpapi_protect=c.protect))
    slot = vault.open_vault(bytes(blob), password="pw").slots[1]
    blob[bytes(blob).index(slot) + 3 + 20] ^= 0x01           # um byte dentro do blob DPAPI do slot
    with pytest.raises(vault.WrongPassword):
        vault.open_vault(bytes(blob), dpapi_unprotect=c.unprotect)


def test_dpapi_nao_conta_no_orcamento_de_kdf():
    c = ContaFalsa()
    o = vault.open_vault(vault.new_vault("s", dpapi_protect=c.protect), dpapi_unprotect=c.unprotect)
    assert vault._slot_kdf_work(o.slots[0]) == 0


# --------------------------------------------------------------------------- #
# Identidade
# --------------------------------------------------------------------------- #
def test_identidade_protegida_so_pela_conta_assina_sem_senha(ident, conta):
    fp = custody.fingerprint()
    custody.protect_identity(use_dpapi=True)
    assert custody.identity_unlockers() == [vault.KIND_DPAPI] and custody.identity_has_dpapi()
    custody.lock_identity()
    assert custody.verify("d", custody.sign("d"))           # nenhuma senha pedida
    assert custody.fingerprint() == fp


def test_em_outra_conta_pede_credencial(ident, conta):
    custody.protect_identity("senha", use_dpapi=True)
    custody.lock_identity()
    conta.trocar()                                           # outra maquina / senha redefinida
    with pytest.raises(custody.IdentityLocked):
        custody.sign("d")
    assert custody.unlock_identity("senha")                  # a senha continua valendo
    assert custody.verify("d", custody.sign("d"))


def test_adicionar_conta_a_identidade_com_senha(ident, conta):
    custody.protect_identity("senha")
    custody.lock_identity()
    custody.add_identity_unlocker(passphrase="senha", new_dpapi=True)
    assert custody.identity_unlockers() == [vault.KIND_PASSWORD, vault.KIND_DPAPI]
    custody.lock_identity()
    assert custody.unlock_identity()                         # sem credencial: abre pela conta
    with pytest.raises(vault.VaultError):
        custody.add_identity_unlocker(passphrase="senha", new_dpapi=True)   # ja tem


def test_remover_a_conta_exige_a_senha_e_a_senha_segue(ident, conta):
    custody.protect_identity("senha", use_dpapi=True)
    with pytest.raises(vault.VaultError):
        custody.remove_identity_unlocker(1, use_dpapi=True)  # entrar pela que sai: recusado
    custody.remove_identity_unlocker(1, "senha")
    assert custody.identity_unlockers() == [vault.KIND_PASSWORD]
    custody.lock_identity()
    assert custody.unlock_identity() is False                # sem a conta, sem credencial: travada
    assert custody.unlock_identity("senha")


def test_remover_a_senha_entrando_pela_conta(ident, conta):
    custody.protect_identity("senha", use_dpapi=True)
    custody.remove_identity_unlocker(0, use_dpapi=True)
    assert custody.identity_unlockers() == [vault.KIND_DPAPI]
    custody.lock_identity()
    assert custody.unlock_identity("senha") is False and custody.unlock_identity()


def test_fora_do_windows_dpapi_recusado(ident, monkeypatch):
    monkeypatch.setattr(dpapi, "available", lambda: False)
    with pytest.raises(vault.VaultError):
        custody.protect_identity(use_dpapi=True)
    assert not custody.is_protected()


def test_backup_de_identidade_so_com_a_conta(ident, conta, tmp_path):
    from notepy import idbackup
    fp = custody.fingerprint()
    custody.protect_identity(use_dpapi=True)
    custody.lock_identity()
    payload = idbackup.collect_local()                       # sem senha: abre pela conta
    assert payload["ed25519_fingerprint"] == fp


# --------------------------------------------------------------------------- #
# DPAPI real (Windows)
# --------------------------------------------------------------------------- #
@so_windows
def test_dpapi_real_ida_e_volta_e_recusa_outra_entropia():
    blob = dpapi.protect(b"k" * 32, b"redoubt-teste")
    assert dpapi.unprotect(blob, b"redoubt-teste") == b"k" * 32
    with pytest.raises(OSError):
        dpapi.unprotect(blob, b"outra")
    with pytest.raises(OSError):
        dpapi.unprotect(blob[:-1] + bytes([blob[-1] ^ 1]), b"redoubt-teste")


@so_windows
def test_identidade_com_dpapi_real_assina_sem_senha(ident):
    custody.protect_identity("senha", use_dpapi=True)
    custody.lock_identity()
    assert custody.verify("d", custody.sign("d"))
