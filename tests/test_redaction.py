"""Testes da Lista de Redacao (notepy/redaction.py) — segredos literais cifrados que o
Modo Redacao tarja. Puro Python, sem Qt. Cofre Argon2id leve (monkeypatch) p/ rodar rapido."""

import pytest

from notepy import custody, redaction, vault


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path))   # cofre da lista no tmp
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_MEMLOG2", 10)           # Argon leve p/ a suite
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_T", 1)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_LANES", 1)
    redaction.lock()
    yield
    redaction.lock()


# --------------------------------------------------------------------------- #
# Ciclo: criar -> salvar -> travar -> destravar (persiste cifrado)
# --------------------------------------------------------------------------- #
def test_roundtrip_persistente(tmp_path):
    assert not redaction.exists()
    redaction.init_new("senha")
    assert redaction.add("batata123") and redaction.add("netflix-2010")
    redaction.save()
    assert redaction.exists()
    redaction.lock()
    assert not redaction.is_unlocked() and redaction.entries() == []
    assert redaction.unlock("senha") is True
    assert set(redaction.entries()) == {"batata123", "netflix-2010"}


def test_senha_errada_nao_destrava():
    redaction.init_new("certa")
    redaction.add("x")
    redaction.save()
    redaction.lock()
    assert redaction.unlock("errada") is False
    assert not redaction.is_unlocked()
    assert redaction.unlock("certa") is True


def test_arquivo_chave_destrava():
    kf = b"meu-arquivo-chave-1234567890"
    redaction.init_new(keyfile=kf)
    redaction.add("segredo")
    redaction.save()
    redaction.lock()
    assert redaction.unlock(keyfile=kf) is True
    assert redaction.entries() == ["segredo"]


def test_disco_cifrado_sem_plaintext():
    redaction.init_new("pw")
    redaction.add("super-secreto-XYZ")
    redaction.save()
    with open(redaction._path(), "rb") as fh:
        blob = fh.read()
    assert b"super-secreto-XYZ" not in blob          # nunca em claro
    assert blob[:5] == b"RDBT4"                        # cifrado (Argon2id por padrao)


# --------------------------------------------------------------------------- #
# Casamento literal (find_in)
# --------------------------------------------------------------------------- #
def test_find_in_acha_todas_ocorrencias():
    redaction.init_new("pw")
    redaction.add("abcd")
    redaction.add("wxyz")
    spans = redaction.find_in("__abcd__wxyz__abcd")
    assert (2, 6) in spans and (8, 12) in spans and (14, 18) in spans
    assert len(spans) == 3


def test_find_in_nao_sobrepoe_a_mesma_string():
    redaction.init_new("pw")
    redaction.add("aaaa")
    assert redaction.find_in("a" * 8) == [(0, 4), (4, 8)]


def test_find_in_travada_retorna_vazio():
    redaction.init_new("pw")
    redaction.add("abcd")
    redaction.lock()
    assert redaction.find_in("abcd abcd") == []


def test_find_in_match_e_o_segredo():
    redaction.init_new("pw")
    redaction.add("senha-do-banco")
    text = "antes senha-do-banco depois"
    (s, e), = redaction.find_in(text)
    assert text[s:e] == "senha-do-banco"              # o trecho casado E o segredo (vira snippet)


# --------------------------------------------------------------------------- #
# Validacao / robustez
# --------------------------------------------------------------------------- #
def test_add_rejeita_invalido():
    redaction.init_new("pw")
    assert redaction.add("") is False
    assert redaction.add("ok") is False               # curto (< _MIN_LEN)
    assert redaction.add("okok") is True
    assert redaction.add("okok") is False             # duplicado
    assert redaction.add("z" * (redaction._MAX_LEN + 1)) is False   # longo demais
    assert redaction.entries() == ["okok"]


def test_remove():
    redaction.init_new("pw")
    redaction.add("aaaa")
    redaction.add("bbbb")
    assert redaction.remove("aaaa") is True
    assert redaction.entries() == ["bbbb"]
    assert redaction.remove("nao-existe") is False


def test_operacoes_exigem_destravada():
    redaction.lock()
    with pytest.raises(vault.VaultError):
        redaction.add("x")
    with pytest.raises(vault.VaultError):
        redaction.save()
    assert redaction.entries() == []                  # nao levanta
    assert redaction.find_in("x") == []               # nao levanta


def test_unlock_sem_cofre_false():
    assert not redaction.exists()
    assert redaction.unlock("pw") is False


def test_init_new_sem_credencial_erra():
    with pytest.raises(vault.VaultError):
        redaction.init_new()


def test_decode_robusto_conteudo_nao_lista():
    # um cofre cujo conteudo NAO e uma lista JSON -> entries vazio, sem crash
    blob = vault.new_vault('{"nao":"e-lista"}', password="pw")
    with open(redaction._path(), "wb") as fh:
        fh.write(blob)
    assert redaction.unlock("pw") is True
    assert redaction.entries() == []


def test_save_re_sela_sem_pedir_senha():
    redaction.init_new("pw")
    redaction.add("aaaa")
    redaction.save()
    redaction.add("bbbb")
    redaction.save()                                  # nao precisa de senha (reseal com key em cache)
    redaction.lock()
    assert redaction.unlock("pw") is True
    assert set(redaction.entries()) == {"aaaa", "bbbb"}


# --------------------------------------------------------------------------- #
# Pos red-team: comprimento minimo + teto de spans (anti-DoS O(n^2))
# --------------------------------------------------------------------------- #
def test_add_rejeita_curto_demais():
    """Segredo de 1-3 chars geraria spans em massa (DoS) — exige >= _MIN_LEN."""
    redaction.init_new("pw")
    assert redaction.add(" ") is False
    assert redaction.add("abc") is False              # 3 < _MIN_LEN(4)
    assert redaction.add("abcd") is True
    assert redaction.entries() == ["abcd"]


def test_decode_filtra_entradas_curtas():
    """Um cofre adulterado com entradas curtas nao reintroduz o vetor de DoS ao destravar."""
    import json
    blob = vault.new_vault(json.dumps([" ", "ok", "credencial-real"]), password="pw")
    with open(redaction._path(), "wb") as fh:
        fh.write(blob)
    assert redaction.unlock("pw") is True
    assert redaction.entries() == ["credencial-real"]  # " " e "ok" (curtos) descartados


def test_find_in_tem_teto_de_spans():
    """Mesmo um literal valido repetido num texto enorme nao devolve lista ilimitada."""
    redaction.init_new("pw")
    redaction.add("aaaa")
    spans = redaction.find_in("a" * 100_000)          # ~25k ocorrencias possiveis (passo +4)
    assert len(spans) <= redaction._MAX_SPANS
