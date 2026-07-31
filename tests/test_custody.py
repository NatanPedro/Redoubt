"""Testes da custodia assinada + trilha (notepy/custody.py) — puro Python, sem Qt."""

import os
import json

import pytest

from notepy import custody, vault


@pytest.fixture
def tmp_identity(tmp_path, monkeypatch):
    """Aponta a identidade/trilha p/ um dir temporario (nao toca no APPDATA real)."""
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def _reset_identity_cache():
    """Zera os caches de sessao das chaves entre testes (sao globais do modulo)."""
    custody.lock_identity()
    custody.lock_recipient()
    yield
    custody.lock_identity()
    custody.lock_recipient()


@pytest.fixture(autouse=True)
def _argon_rapido(monkeypatch):
    """Identidade protegida usa o Cofre (Argon2id); params leves p/ a suite rodar rapido."""
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_MEMLOG2", 10)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_T", 1)
    monkeypatch.setattr(vault, "_DEFAULT_ARGON_LANES", 1)


# --------------------------------------------------------------------------- #
# Assinatura
# --------------------------------------------------------------------------- #
def test_sign_verify_roundtrip(tmp_identity):
    sig = custody.sign("conteudo importante")
    assert custody.verify("conteudo importante", sig)


def test_verify_detecta_adulteracao(tmp_identity):
    sig = custody.sign("original")
    assert not custody.verify("original alterado", sig)     # 1 char muda -> falha


def test_verify_com_chave_publica_exportada(tmp_identity):
    sig = custody.sign("x")
    pub = custody.public_key_b64()
    assert custody.verify("x", sig, pub)
    assert not custody.verify("y", sig, pub)


def test_chave_de_outra_instalacao_nao_verifica(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir(); (tmp_path / "b").mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "a"))
    sig = custody.sign("msg"); pub_a = custody.public_key_b64()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "b"))
    pub_b = custody.public_key_b64()
    assert pub_a != pub_b
    assert not custody.verify("msg", sig, pub_b)             # sig de A nao confere com B


def test_chave_persiste_entre_chamadas(tmp_identity):
    assert custody.public_key_b64() == custody.public_key_b64()
    assert len(custody.fingerprint()) == 16


def test_verify_entrada_lixo_nao_crasha(tmp_identity):
    assert custody.verify("x", "nao-e-base64-valido!!!") is False
    assert custody.verify("x", "YWJj", "chave-lixo") is False


# --------------------------------------------------------------------------- #
# Identidade protegida por senha (Cofre RDBT2, opt-in)
# --------------------------------------------------------------------------- #
def test_protect_preserva_fingerprint(tmp_identity):
    custody.sign("x")                                   # cria a identidade legada
    fp, pub = custody.fingerprint(), custody.public_key_b64()
    assert not custody.is_protected()
    custody.protect_identity("senha-mestra")
    assert custody.is_protected()
    assert custody.fingerprint() == fp                  # MESMA chave preservada
    assert custody.public_key_b64() == pub
    assert not os.path.exists(custody._pem_path())      # PEM nu removido do disco


def test_protegida_assina_so_com_senha(tmp_identity):
    custody.sign("x")
    custody.protect_identity("pw")
    custody.lock_identity()                             # simula nova sessao
    with pytest.raises(custody.IdentityLocked):
        custody.sign("doc")                            # sem senha -> bloqueado
    assert custody.unlock_identity("pw")
    sig = custody.sign("doc")                          # destravada -> assina
    assert custody.verify("doc", sig)


def test_protegida_senha_errada(tmp_identity):
    custody.sign("x")
    custody.protect_identity("certa")
    custody.lock_identity()
    assert custody.unlock_identity("errada") is False
    with pytest.raises(custody.IdentityLocked):
        custody.sign("doc")
    assert custody.verify("doc", custody.sign("doc", passphrase="certa"))  # senha inline


def test_protegida_fingerprint_e_verify_sem_senha(tmp_identity):
    custody.sign("x")
    fp = custody.fingerprint()
    sig = custody.sign("doc")                           # assina ANTES de proteger
    custody.protect_identity("pw")
    custody.lock_identity()                             # travada, sem senha em cache
    assert custody.fingerprint() == fp                 # fingerprint NAO pede senha
    assert len(custody.public_key_b64()) > 0           # pubkey NAO pede senha
    assert custody.verify("doc", sig)                  # verify NAO pede senha


def test_unprotect_volta_pem(tmp_identity):
    custody.sign("x")
    fp = custody.fingerprint()
    custody.protect_identity("pw")
    custody.unprotect_identity("pw")
    assert not custody.is_protected()
    assert os.path.exists(custody._pem_path())
    assert custody.fingerprint() == fp
    custody.lock_identity()
    assert custody.verify("d", custody.sign("d"))      # volta a assinar sem senha


def test_multi_fator_senha_e_arquivo_chave(tmp_identity):
    custody.sign("x")
    custody.protect_identity("senha1")
    custody.add_identity_unlocker(passphrase="senha1", new_keyfile=b"arquivo-chave-secreto")
    assert sorted(custody.identity_unlockers()) == [vault.KIND_PASSWORD, vault.KIND_KEYFILE]
    custody.lock_identity()
    assert custody.unlock_identity(keyfile=b"arquivo-chave-secreto")   # destrava so com keyfile
    assert custody.verify("d", custody.sign("d"))
    custody.lock_identity()
    assert custody.unlock_identity("senha1")            # e a senha original tambem
    assert custody.unlock_identity(keyfile=b"arquivo-errado") is False


def test_protect_exige_credencial_e_nao_duplica(tmp_identity):
    custody.sign("x")
    with pytest.raises(vault.VaultError):
        custody.protect_identity()                      # sem senha nem keyfile
    custody.protect_identity("pw")
    with pytest.raises(vault.VaultError):
        custody.protect_identity("outra")               # ja protegida


# --- Endurecimento pos red-team da identidade protegida ---
def test_pem_orfao_nao_apaga_o_cofre(tmp_identity, monkeypatch):
    """INVARIANTE CORRIGIDO (red-team): se a remocao do PEM em claro falhar, o cofre — que ja foi
    VERIFICADO — permanece, e o erro e especifico (IdentityClearCopyRemains).

    Antes isto fazia ROLLBACK apagando o cofre; combinado com o wipe do PEM (o modo de falha real do
    Windows: wipe ok, remove bloqueado), a identidade Ed25519 ficava IRRECUPERAVEL."""
    custody.sign("x")                                   # cria a identidade legada (PEM existe)
    fp = custody.fingerprint()
    monkeypatch.setattr(custody, "_secure_remove", lambda p: None)   # simula remocao que falhou
    with pytest.raises(custody.IdentityClearCopyRemains):
        custody.protect_identity("pw")
    assert os.path.exists(custody._pem_path())          # PEM em claro ainda la (detectado)...
    assert custody.identity_has_orphan_pem()
    assert custody.is_protected()                       # ...e o cofre PERMANECE (chave preservada)
    custody.lock_identity()
    assert custody.unlock_identity("pw")
    assert custody.fingerprint() == fp


def test_unprotect_nao_apaga_o_pem_se_o_cofre_resistir(tmp_identity, monkeypatch):
    """Espelho corrigido: se remover o cofre falhar no unprotect, o PEM NAO e apagado (era o
    caminho de PERDA TOTAL: o cofre virava lixo pelo wipe e o PEM era removido depois)."""
    custody.sign("x")
    custody.protect_identity("pw")
    fp = custody.fingerprint()
    real_remove = os.remove
    monkeypatch.setattr(custody.os, "remove", _remove_travado_em([custody._vault_path()]))
    with pytest.raises(vault.VaultError):
        custody.unprotect_identity("pw")
    monkeypatch.setattr(custody.os, "remove", real_remove)
    assert custody.is_protected()                       # continua protegido (cofre intacto)
    assert os.path.exists(custody._pem_path())          # e o PEM em claro NAO foi destruido
    custody.lock_identity()
    assert custody.unlock_identity("pw")                # o cofre segue abrindo (nao virou lixo)
    assert custody.fingerprint() == fp


def test_orphan_pem_detectado_e_curado_no_unlock(tmp_identity):
    """Coexistencia rdbt+pem (proteger morto no meio): detectada e auto-curada ao destravar."""
    from cryptography.hazmat.primitives import serialization as _ser
    custody.sign("x")
    custody.protect_identity("pw")
    key = custody._session_key                          # a chave real (cacheada)
    pem = key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption())
    with open(custody._pem_path(), "wb") as fh:         # simula o PEM nu residual da MESMA chave
        fh.write(pem)
    assert custody.identity_has_orphan_pem()            # estado inconsistente detectado
    custody.lock_identity()
    assert custody.unlock_identity("pw")                # destravar -> auto-cura
    assert not os.path.exists(custody._pem_path())      # copia em claro removida (mesma chave)
    assert not custody.identity_has_orphan_pem()


def test_orphan_pem_de_chave_diferente_nao_e_removido(tmp_identity):
    """Conservador: se o PEM coexistente for de OUTRA chave, NAO apaga (nao destroi material alheio)."""
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    custody.sign("x")
    custody.protect_identity("pw")
    outra = Ed25519PrivateKey.generate()
    pem = outra.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption())
    with open(custody._pem_path(), "wb") as fh:
        fh.write(pem)
    custody.lock_identity()
    assert custody.unlock_identity("pw")
    assert os.path.exists(custody._pem_path())          # chave diferente: preservado


def test_pub_corrompida_nao_crasha(tmp_identity):
    custody.sign("x")
    custody.protect_identity("pw")
    custody.lock_identity()
    with open(custody._pub_path(), "w", encoding="ascii") as fh:
        fh.write("@@@ nao eh base64 @@@")
    with pytest.raises(custody.CustodyError):           # erro semantico, NAO binascii cru
        custody.fingerprint()
    assert custody.unlock_identity("pw")                # destravar corrige a pub e usa a chave real
    assert len(custody.fingerprint()) == 16


def test_cofre_da_identidade_corrompido_unlock_false(tmp_identity):
    custody.sign("x")
    custody.protect_identity("pw")
    custody.lock_identity()
    with open(custody._vault_path(), "wb") as fh:
        fh.write(b"isto nao eh um cofre RDBT2 valido")
    assert custody.unlock_identity("pw") is False       # nao crasha, so falha


def test_pub_adulterada_e_corrigida_no_unlock(tmp_identity):
    import base64
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    custody.sign("x")
    fp = custody.fingerprint()
    custody.protect_identity("pw")
    custody.lock_identity()
    outra = Ed25519PrivateKey.generate().public_key().public_bytes(
        _ser.Encoding.Raw, _ser.PublicFormat.Raw)
    with open(custody._pub_path(), "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(outra).decode())
    assert custody.fingerprint() != fp                  # travada: reflete o arquivo (limitacao honesta)
    assert custody.unlock_identity("pw")                # binding: ao destravar, usa a chave REAL...
    assert custody.fingerprint() == fp                  # ...e regrava a pub correta


# --------------------------------------------------------------------------- #
# Trilha de auditoria encadeada
# --------------------------------------------------------------------------- #
def test_auditoria_encadeada(tmp_identity):
    custody.log_event("abriu", "a.txt", "h1", ts="2026-01-01T00:00:00+00:00")
    custody.log_event("selou", "a.txt", "h2", ts="2026-01-01T00:01:00+00:00")
    e = custody.read_audit()
    assert len(e) == 2
    assert e[1]["prev"] == e[0]["hash"]                     # encadeado
    ok, idx = custody.verify_chain()
    assert ok and idx == -1


def test_auditoria_detecta_adulteracao(tmp_identity):
    custody.log_event("abriu", "a.txt", "h1", ts="2026-01-01T00:00:00+00:00")
    custody.log_event("selou", "a.txt", "h2", ts="2026-01-01T00:01:00+00:00")
    custody.log_event("queimou", "b.txt", "h3", ts="2026-01-01T00:02:00+00:00")
    p = custody._audit_path()
    lines = open(p, encoding="utf-8").read().splitlines()
    bad = json.loads(lines[1]); bad["detail"] = "ADULTERADO"  # mexe num evento passado
    lines[1] = json.dumps(bad, ensure_ascii=False)
    open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    ok, idx = custody.verify_chain()
    assert not ok and idx == 1                              # cadeia quebra na entrada 1


def test_auditoria_vazia(tmp_identity):
    assert custody.read_audit() == []
    assert custody.verify_chain() == (True, -1)


# --------------------------------------------------------------------------- #
# Trilha v2: seq, assinatura best-effort, ancora anti-reset
# --------------------------------------------------------------------------- #
def test_trilha_tem_seq_e_assinatura(tmp_identity):
    custody.log_event("abriu", "a.txt", "h1")
    custody.log_event("salvou", "a.txt", "h2")
    e = custody.read_audit()
    assert [x["seq"] for x in e] == [1, 2]
    assert all(x["sig"] for x in e)                     # nao-protegida: assina (best-effort)
    assert custody.verify_chain() == (True, -1)
    assert custody.audit_stats() == {"total": 2, "signed": 2, "head_seq": 2}


def test_seq_no_hash_detecta_remocao_no_meio(tmp_identity):
    for i in range(3):
        custody.log_event("ev", f"e{i}", f"h{i}", ts=f"2026-01-01T00:0{i}:00+00:00")
    p = custody._audit_path()
    lines = open(p, encoding="utf-8").read().splitlines()
    del lines[1]                                        # remove a entrada do meio
    open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    ok, _ = custody.verify_chain()
    assert not ok                                       # cadeia quebra (prev e/ou seq)


def test_assinatura_vazia_quando_protegida_e_travada(tmp_identity):
    custody.sign("x")
    custody.protect_identity("pw")
    custody.lock_identity()
    e = custody.log_event("abriu", "a.txt", "h1")       # best-effort: nao assina (travada)
    assert e["sig"] == ""
    assert custody.verify_chain() == (True, -1)         # encadeamento ok mesmo sem sig


def test_ancora_consistente(tmp_identity):
    custody.log_event("a", "1", "h1")
    custody.log_event("b", "2", "h2")
    anchor = custody.export_anchor(ts="2026-01-01T00:00:00+00:00")
    custody.log_event("c", "3", "h3")                   # +1 evento depois de ancorar
    r = custody.check_anchor(anchor)
    assert r["sig_ok"] and r["present"] and r["head_match"] and r["ok"]


def test_ancora_detecta_reset(tmp_identity):
    custody.log_event("a", "1", "h1")
    custody.log_event("b", "2", "h2")
    anchor = custody.export_anchor()
    os.remove(custody._audit_path())                    # RESET: apaga a trilha inteira
    custody.log_event("novo", "x", "hx")                # recomeca do zero
    r = custody.check_anchor(anchor)
    assert r["sig_ok"]                                  # a ancora em si e valida...
    assert not r["present"] and not r["ok"]             # ...mas a trilha nao alcanca o seq ancorado


def test_ancora_detecta_divergencia(tmp_identity):
    custody.log_event("a", "1", "h1")
    custody.log_event("b", "2", "h2")
    anchor = custody.export_anchor()
    os.remove(custody._audit_path())                    # reescreve com eventos DIFERENTES
    custody.log_event("X", "9", "h9")
    custody.log_event("Y", "8", "h8")
    r = custody.check_anchor(anchor)
    assert r["sig_ok"] and r["present"]                 # alcanca o seq 2...
    assert not r["head_match"] and not r["ok"]          # ...mas o hash no ponto diverge


def test_ancora_adulterada_falha_assinatura(tmp_identity):
    custody.log_event("a", "1", "h1")
    anchor = custody.export_anchor()
    anchor["head_hash"] = "0" * 64                      # adultera o valor ancorado
    r = custody.check_anchor(anchor)
    assert not r["sig_ok"] and not r["ok"]              # a assinatura nao cobre o valor adulterado


def test_ancora_malformada_nao_crasha(tmp_identity):
    assert custody.check_anchor({})["detail"]
    assert custody.check_anchor({})["ok"] is False


def test_export_anchor_protegida_pede_senha(tmp_identity):
    custody.sign("x")
    custody.protect_identity("pw")
    custody.lock_identity()
    custody.log_event("abriu", "a.txt", "h1")           # trilha nao-vazia (sig vazio, travada)
    with pytest.raises(custody.IdentityLocked):
        custody.export_anchor()                         # travada: assinar a ancora pede senha
    custody.unlock_identity("pw")
    anchor = custody.export_anchor()
    assert custody.check_anchor(anchor)["ok"]


def test_export_anchor_trilha_vazia_erra(tmp_identity):
    with pytest.raises(custody.CustodyError):
        custody.export_anchor()                         # nada a ancorar


def test_ancora_forjada_por_outra_chave_rejeitada(tmp_path, monkeypatch):
    """Binding (licao do release nº1): ancora assinada por OUTRA chave NAO e aceita como autentica."""
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "A"))
    (tmp_path / "A").mkdir()
    custody.log_event("a", "1", "h1")
    fp_a = custody.fingerprint()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "B"))  # atacante
    (tmp_path / "B").mkdir()
    custody.log_event("x", "9", "h9")
    anchor_b = custody.export_anchor()                  # assinada pela chave B
    r = custody.check_anchor(anchor_b, expected_fingerprint=fp_a)
    assert r["sig_ok"]                                  # internamente valida (chave B)...
    assert r["fingerprint"] != fp_a
    assert not r["identity_match"] and not r["ok"]      # ...mas NAO e a identidade esperada -> rejeitada


def test_ancora_default_amarra_identidade_local(tmp_identity):
    custody.log_event("a", "1", "h1")
    anchor = custody.export_anchor()
    r = custody.check_anchor(anchor)                    # sem expected: usa a identidade LOCAL
    assert r["identity_match"] and r["ok"]


def test_trilha_com_linha_nao_dict_nao_crasha(tmp_identity):
    custody.log_event("a", "1", "h1")
    with open(custody._audit_path(), "a", encoding="utf-8") as fh:
        fh.write("[1, 2, 3]\n\"so uma string\"\n42\n")  # linhas JSON validas mas NAO-objeto
    assert custody.audit_stats()["total"] == 1          # nao-dicts descartados
    assert custody.verify_chain()[0] is True
    anchor = custody.export_anchor()
    assert custody.check_anchor(anchor)["ok"]           # nenhuma funcao crashou


def test_export_anchor_recusa_head_sem_hash(tmp_identity):
    import json as _json
    e = {"ts": "t", "event": "x", "detail": "", "content_hash": "", "prev": ""}  # legada SEM hash
    with open(custody._audit_path(), "w", encoding="utf-8") as fh:
        fh.write(_json.dumps(e) + "\n")
    with pytest.raises(custody.CustodyError):
        custody.export_anchor()                         # cabeca sem hash valido


def test_check_anchor_pega_cadeia_quebrada(tmp_identity):
    import json as _json
    for i in range(3):
        custody.log_event("ev", f"e{i}", f"h{i}", ts=f"2026-01-01T00:0{i}:00+00:00")
    anchor = custody.export_anchor()                    # seq=3
    lines = open(custody._audit_path(), encoding="utf-8").read().splitlines()
    bad = _json.loads(lines[1]); bad["detail"] = "ADULTERADO"
    lines[1] = _json.dumps(bad)
    open(custody._audit_path(), "w", encoding="utf-8").write("\n".join(lines) + "\n")
    r = custody.check_anchor(anchor)
    assert not r["chain_ok"] and not r["ok"]            # adulteracao interna detectada


def test_check_anchor_nao_cria_identidade(tmp_path, monkeypatch):
    """Verificar e READ-ONLY: numa instalacao limpa, check_anchor NAO materializa chave no disco."""
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "A"))
    (tmp_path / "A").mkdir()
    custody.log_event("a", "1", "h1")
    anchor = custody.export_anchor()
    clean = tmp_path / "clean"
    clean.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(clean))
    custody.lock_identity()
    r = custody.check_anchor(anchor)                    # sem identidade local
    assert not os.path.exists(os.path.join(str(clean), "identity.ed25519"))   # NAO criou a privada
    assert not os.path.exists(os.path.join(str(clean), "identity.pub"))       # nem a publica
    assert r["identity_match"] is False                 # sem identidade local para comparar


def test_trilha_legada_sem_seq_ainda_valida(tmp_identity):
    """Compat: entradas no formato antigo (sem seq/sig) continuam validas em verify_chain."""
    import json as _json
    e1 = {"ts": "2026-01-01T00:00:00+00:00", "event": "abriu", "detail": "a", "content_hash": "h1", "prev": ""}
    e1["hash"] = custody._entry_hash(e1)                # hash legado (sem seq)
    e2 = {"ts": "2026-01-01T00:01:00+00:00", "event": "salvou", "detail": "a", "content_hash": "h2", "prev": e1["hash"]}
    e2["hash"] = custody._entry_hash(e2)
    with open(custody._audit_path(), "w", encoding="utf-8") as fh:
        fh.write(_json.dumps(e1) + "\n" + _json.dumps(e2) + "\n")
    assert custody.verify_chain() == (True, -1)         # legado sem seq: cadeia intacta


# --------------------------------------------------------------------------- #
# Identidade de destinatario (X25519)
# --------------------------------------------------------------------------- #
def test_recipient_keypair_persiste(tmp_identity):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    assert not custody.recipient_exists()
    pub1 = custody.recipient_public_b64()
    assert custody.recipient_exists()
    assert custody.recipient_public_b64() == pub1        # nao regenera por cima
    assert len(base64.b64decode(pub1)) == 32
    # a privada bate com a publica exportada
    priv = X25519PrivateKey.from_private_bytes(custody.recipient_private_bytes())
    derived = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert base64.b64encode(derived).decode() == pub1
    assert len(custody.recipient_fingerprint()) == 16


def test_recipient_corrompido_erra(tmp_identity):
    with open(custody._recipient_path(), "wb") as fh:
        fh.write(b"curto")                               # tamanho invalido -> NAO regenera, erra
    with pytest.raises(custody.CustodyError):
        custody.recipient_public_b64()


def test_recipient_seal_open_roundtrip(tmp_identity):
    import base64
    pub = base64.b64decode(custody.recipient_public_b64())
    blob = vault.new_vault("para mim", recipient=pub)
    assert vault.open_vault(blob, x25519_private=custody.recipient_private_bytes()).text == "para mim"


# --------------------------------------------------------------------------- #
# Chave de destinatario PROTEGIDA por senha (opt-in) — fecha o "local em claro"
# --------------------------------------------------------------------------- #
def test_recipient_protect_remove_claro_e_preserva_fingerprint(tmp_identity):
    fp_antes = custody.recipient_fingerprint()
    pub_antes = custody.recipient_public_b64()
    assert os.path.exists(custody._recipient_path())          # em claro no disco
    custody.protect_recipient("senha-x")
    assert custody.recipient_is_protected()
    assert not os.path.exists(custody._recipient_path())      # copia em claro REMOVIDA
    assert os.path.exists(custody._recipient_vault_path())
    assert os.path.exists(custody._recipient_pub_path())
    assert custody.recipient_fingerprint() == fp_antes        # MESMA identidade
    assert custody.recipient_public_b64() == pub_antes


def test_recipient_protegida_exporta_pub_sem_senha(tmp_identity):
    """Travada, exportar a PUBLICA e selar para alguem seguem funcionando (nao pedem senha)."""
    pub_antes = custody.recipient_public_b64()
    custody.protect_recipient("senha-x")
    custody.lock_recipient()
    assert not custody.recipient_unlocked()
    assert custody.recipient_public_b64() == pub_antes        # veio de recipient.pub, sem senha
    assert len(custody.recipient_fingerprint()) == 16


def test_recipient_protegida_privada_exige_senha(tmp_identity):
    custody.protect_recipient("senha-x")
    custody.lock_recipient()
    with pytest.raises(custody.RecipientLocked):
        custody.recipient_private_bytes()                    # travada: nao entrega a privada
    with pytest.raises(vault.WrongPassword):
        custody.recipient_private_bytes("errada")
    assert len(custody.recipient_private_bytes("senha-x")) == 32     # com a senha certa, ok


def test_recipient_unlock_credencial_errada_falha(tmp_identity):
    custody.protect_recipient("senha-x")
    custody.lock_recipient()
    assert custody.unlock_recipient("errada") is False
    assert not custody.recipient_unlocked()
    assert custody.unlock_recipient("senha-x") is True
    assert custody.recipient_unlocked()


def test_recipient_protegida_ainda_abre_cofre_selado(tmp_identity):
    """O TESTE CRITICO: proteger a chave NAO pode perder acesso ao que ja foi selado pra voce."""
    import base64
    pub = base64.b64decode(custody.recipient_public_b64())
    blob = vault.new_vault("segredo do destinatario", recipient=pub)
    custody.protect_recipient("senha-x")
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")
    opened = vault.open_vault(blob, x25519_private=custody.recipient_private_bytes())
    assert opened.text == "segredo do destinatario"


def test_recipient_unprotect_volta_para_claro(tmp_identity):
    fp = custody.recipient_fingerprint()
    custody.protect_recipient("senha-x")
    custody.lock_recipient()
    custody.unprotect_recipient("senha-x")
    assert not custody.recipient_is_protected()
    assert os.path.exists(custody._recipient_path())
    assert custody.recipient_fingerprint() == fp             # identidade preservada
    assert len(custody.recipient_private_bytes()) == 32       # sem senha de novo


def test_recipient_add_unlocker_senha_de_backup(tmp_identity):
    custody.protect_recipient("senha-x")
    custody.add_recipient_unlocker(passphrase="senha-x", new_password="backup-y")
    custody.lock_recipient()
    assert custody.unlock_recipient("backup-y") is True      # a 2a senha tambem abre
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x") is True        # e a original segue valendo


def test_recipient_orfao_em_claro_e_limpo_no_unlock(tmp_identity):
    """Residuo de um proteger interrompido (raw + cofre coexistindo) e apagado ao destravar."""
    raw_antes = custody.recipient_private_bytes()
    custody.protect_recipient("senha-x")
    with open(custody._recipient_path(), "wb") as fh:         # simula a copia em claro que sobrou
        fh.write(raw_antes)
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")
    assert not os.path.exists(custody._recipient_path())      # curado: sem copia em claro


def test_recipient_exists_com_apenas_o_cofre(tmp_identity):
    """recipient_exists() enxerga a chave protegida (senao a UI nem tentaria destravar)."""
    custody.protect_recipient("senha-x")
    custody.lock_recipient()
    assert not os.path.exists(custody._recipient_path())
    assert custody.recipient_exists()


def test_recipient_protect_duas_vezes_erra(tmp_identity):
    custody.protect_recipient("senha-x")
    with pytest.raises(vault.VaultError):
        custody.protect_recipient("outra")                    # ja protegida
    with pytest.raises(vault.VaultError):
        custody.unprotect_recipient("errada")                 # credencial errada nao desprotege


def test_recipient_protect_sem_credencial_erra(tmp_identity):
    with pytest.raises(vault.VaultError):
        custody.protect_recipient("")
    assert not custody.recipient_is_protected()


# --------------------------------------------------------------------------- #
# Regressoes do red-team da protecao X25519 (F1..F10 / L1)
# --------------------------------------------------------------------------- #
def _remove_travado_em(paths):
    """Simula o modo de falha REAL do Windows (lock de antivirus/sync): o WIPE passa e so o
    `os.remove` falha, e apenas nos caminhos indicados.

    Isto importa: a 1a versao destes testes falhava ANTES do wipe, e por isso passava verde
    enquanto o wipe-ok/remove-falha destruia a chave de verdade (achado F1-H do red-team)."""
    real = os.remove
    alvos = {os.path.normcase(str(p)) for p in paths}

    def fake(p, *a, **k):
        if os.path.normcase(str(p)) in alvos:
            raise OSError("lock do AV")
        return real(p, *a, **k)
    return fake



def test_rt_f1_falha_ao_gravar_a_pub_nao_atrapalha(tmp_identity, monkeypatch):
    """F1: a publica agora e gravada DEPOIS do cofre verificado e e best-effort — ela e derivada da
    privada, entao falhar ali nao pode nem abortar a protecao nem brickar a instalacao (antes,
    gravada primeiro, uma falha no cofre deixava uma 'pub orfa' que travava a tripwire para sempre)."""
    priv = custody.recipient_private_bytes()
    fp = custody.recipient_fingerprint()
    real_write = custody._write_recipient_pub             # captura ANTES do patch
    monkeypatch.setattr(custody, "_write_recipient_pub",
                        lambda *_a, **_k: (_ for _ in ()).throw(OSError("pub read-only")))
    custody.protect_recipient("senha-x")                  # protege mesmo assim
    assert custody.recipient_is_protected()
    assert not custody.recipient_has_orphan_raw()         # a copia em claro foi removida
    assert custody.recipient_private_bytes() == priv       # e a chave e a mesma
    monkeypatch.setattr(custody, "_write_recipient_pub", real_write)
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")            # o unlock reconstroi a publica
    assert custody.recipient_fingerprint() == fp


def test_rt_f1_raw_travado_protege_e_avisa_sem_perder_a_chave(tmp_identity, monkeypatch):
    """F1 (2a rodada): se a copia em claro nao puder ser removida, a prioridade e NUNCA PERDER A
    CHAVE. Antes o rollback apagava o cofre DEPOIS do wipe do raw e a chave ficava irrecuperavel.
    Agora: cofre (ja verificado) fica, erro ALTO e especifico, e o estado e detectavel/curavel."""
    fp = custody.recipient_fingerprint()
    priv = custody.recipient_private_bytes()
    real_remove = os.remove                                # NAO usar monkeypatch.undo(): ele
    monkeypatch.setattr(custody.os, "remove",              # desfaria tambem o _data_dir do fixture,
                        _remove_travado_em([custody._recipient_path()]))   # caindo no APPDATA real
    with pytest.raises(custody.RecipientClearCopyRemains):
        custody.protect_recipient("senha-x")
    assert custody.recipient_is_protected()               # o cofre PROVADO permanece
    assert custody.recipient_has_orphan_raw()             # e o residuo em claro e DETECTADO
    # O residuo NAO pode ser uma chave valida diferente ("isca"): o wipe zera o arquivo, senao 32
    # bytes aleatorios seriam adotados em silencio como a sua nova identidade (achado F1-C).
    assert os.path.getsize(custody._recipient_path()) == 0
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")            # a chave nao se perdeu
    assert custody.recipient_private_bytes() == priv
    assert custody.recipient_fingerprint() == fp
    monkeypatch.setattr(custody.os, "remove", real_remove)   # AV fora do caminho: o unlock cura
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")
    assert not custody.recipient_has_orphan_raw()


def test_rt_f1_interrupcao_no_wipe_nao_perde_a_chave(tmp_identity, monkeypatch):
    """F4/C1.g: interrupcao durante o wipe deixa cofre + raw — estado detectavel, chave intacta
    (e NUNCA o cofre apagado depois de um wipe parcial)."""
    priv = custody.recipient_private_bytes()
    real_remove = custody._secure_remove
    monkeypatch.setattr(custody, "_secure_remove",
                        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        custody.protect_recipient("senha-x")
    assert custody.recipient_is_protected()
    assert custody.recipient_has_orphan_raw()
    monkeypatch.setattr(custody, "_secure_remove", real_remove)
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")
    assert custody.recipient_private_bytes() == priv       # a chave sobreviveu


def test_rt_f1_cofre_que_nao_verifica_e_desfeito(tmp_identity, monkeypatch):
    """Unico rollback SEGURO: a prova do cofre falha ANTES de qualquer destruicao -> desfaz o
    cofre, e a copia em claro (intacta) segue sendo a verdade."""
    priv = custody.recipient_private_bytes()
    monkeypatch.setattr(custody, "_open_protected_recipient",
                        lambda *_a, **_k: (_ for _ in ()).throw(vault.VaultError("cofre ruim")))
    with pytest.raises(vault.VaultError):
        custody.protect_recipient("senha-x")
    assert not custody.recipient_is_protected()           # cofre nao verificado foi removido
    assert custody.recipient_private_bytes() == priv       # chave em claro preservada


def test_rt_unprotect_cofre_travado_nao_perde_a_identidade(tmp_identity, monkeypatch):
    """Perda TOTAL que o red-team provou: unprotect sobrescrevia o cofre e depois apagava o raw.
    Agora o cofre sai com os.remove (sem wipe) e o raw NUNCA e apagado se o cofre resistir."""
    custody.protect_recipient("senha-x")
    priv = custody.recipient_private_bytes()
    real_remove = os.remove
    monkeypatch.setattr(custody.os, "remove",
                        lambda *_a, **_k: (_ for _ in ()).throw(OSError("lock do AV")))
    with pytest.raises(vault.VaultError):
        custody.unprotect_recipient("senha-x")
    monkeypatch.setattr(custody.os, "remove", real_remove)   # so isto (undo() derrubaria _data_dir)
    assert custody.recipient_is_protected()               # segue protegida (cofre intacto)
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")            # o cofre NAO foi corrompido
    assert custody.recipient_private_bytes() == priv       # nem a identidade se perdeu


def test_rt_f3_protect_tambem_respeita_o_tripwire(tmp_identity):
    """F3 (2a rodada): a tripwire era furada por protect_recipient, que decidia por
    recipient_exists() — no estado 'pub orfa' ele gerava uma chave NOVA em silencio."""
    custody.recipient_public_b64()
    fp = custody.recipient_fingerprint()
    os.remove(custody._recipient_path())                   # privada em quarentena; pub ficou
    with pytest.raises(custody.CustodyError):
        custody.protect_recipient("senha-x")               # nao inventa outra chave
    assert not custody.recipient_is_protected()
    assert not os.path.exists(custody._recipient_path())
    import base64 as _b64
    import hashlib as _hl
    with open(custody._recipient_pub_path(), encoding="ascii") as fh:
        assert _hl.sha256(_b64.b64decode(fh.read().strip())).hexdigest()[:16] == fp   # pub intacta


def test_rt_f4_residuo_tmp_e_detectado_e_curado(tmp_identity):
    """F4 (2a rodada): um `.tmp` de escrita atomica interrompida guarda os 32 bytes EM CLARO e
    passava invisivel ao detector e ao curador."""
    raw = custody.recipient_private_bytes()
    custody.protect_recipient("senha-x")
    assert not custody.recipient_has_orphan_raw()
    with open(custody._recipient_path() + ".tmp", "wb") as fh:   # residuo irmao
        fh.write(raw)
    assert custody.recipient_has_orphan_raw()             # AGORA detectado
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")
    assert not os.path.exists(custody._recipient_path() + ".tmp")   # e curado


def test_rt_f2_pub_nao_ascii_nao_derruba_o_unlock(tmp_identity):
    """F2 (2a rodada): a leitura da pub em ASCII capturava so OSError, entao um byte nao-ASCII
    (BOM/0xFF/binario) levantava UnicodeDecodeError — que escapava e ABORTAVA o processo."""
    custody.protect_recipient("senha-x")
    priv = custody.recipient_private_bytes()
    custody.lock_recipient()
    with open(custody._recipient_pub_path(), "wb") as fh:
        fh.write(b"\xff\xfe\x00binario")
    assert custody.unlock_recipient("senha-x") is True     # nao explode
    assert custody.recipient_private_bytes() == priv        # e a sessao FOI setada (nao nega acesso)


def test_rt_secure_remove_limpa_somente_leitura(tmp_identity):
    """R8: com o atributo somente-leitura, a limpeza da copia em claro falhava EM SILENCIO."""
    import stat as _stat
    raw = custody.recipient_private_bytes()
    custody.protect_recipient("senha-x")
    p = custody._recipient_path()
    with open(p, "wb") as fh:
        fh.write(raw)
    os.chmod(p, _stat.S_IREAD)                             # somente-leitura
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")
    assert not os.path.exists(p)                           # curado mesmo somente-leitura


def test_rt_f8_proteger_de_zero_nunca_grava_a_privada_em_claro(tmp_identity, monkeypatch):
    """F8: sem chave previa, proteger gera em MEMORIA — o raw nunca deve ser escrito no disco."""
    escritos: list[str] = []
    real = custody._atomic_write
    monkeypatch.setattr(custody, "_atomic_write",
                        lambda p, d: (escritos.append(os.path.basename(p)), real(p, d))[1])
    assert not custody.recipient_exists()
    custody.protect_recipient("senha-x")
    assert "recipient.x25519" not in escritos             # a privada nunca tocou o disco em claro
    assert "recipient.rdbt" in escritos
    assert custody.recipient_is_protected()
    assert not os.path.exists(custody._recipient_path())


def test_rt_f2_cofre_da_chave_ilegivel_nao_levanta_oserror(tmp_identity):
    """F2b (ALTO): arquivo ilegivel (lock de AV/ACL) nao pode virar OSError cru — derrubaria a UI."""
    custody.protect_recipient("senha-x")
    custody.lock_recipient()
    p = custody._recipient_vault_path()
    os.remove(p)
    os.mkdir(p)                                           # diretorio no lugar do arquivo -> OSError
    assert custody.unlock_recipient("senha-x") is False    # tratado, nao explode
    with pytest.raises(vault.VaultError):
        custody.unprotect_recipient("senha-x")
    with pytest.raises(vault.VaultError):
        custody.add_recipient_unlocker(passphrase="senha-x", new_password="backup")
    with pytest.raises(vault.WrongPassword):
        custody.recipient_private_bytes("senha-x")


def test_rt_f2_pub_ilegivel_nao_derruba_o_fingerprint(tmp_identity):
    """F2a: com a pub ausente/lixo e a chave travada, a API erra com CustodyError (tratavel)."""
    custody.protect_recipient("senha-x")
    custody.lock_recipient()
    with open(custody._recipient_pub_path(), "w", encoding="ascii") as fh:
        fh.write("@@@ nao e base64 @@@")
    with pytest.raises(custody.CustodyError):
        custody.recipient_fingerprint()
    os.remove(custody._recipient_pub_path())
    with pytest.raises(custody.CustodyError):
        custody.recipient_public_b64()
    assert custody.unlock_recipient("senha-x") is True     # destravar reconstroi a pub
    assert len(custody.recipient_fingerprint()) == 16


def test_rt_f3_chave_removida_nao_regenera_silenciosamente(tmp_identity):
    """F3 (MEDIO): perder o recipient.rdbt NAO pode gerar uma chave nova em claro — isso trocaria
    sua identidade e perderia o acesso aos cofres selados pra voce. Tem que ERRAR alto."""
    custody.protect_recipient("senha-x")
    fp = custody.recipient_fingerprint()
    custody.lock_recipient()
    os.rename(custody._recipient_vault_path(), custody._recipient_vault_path() + ".bak")
    with pytest.raises(custody.CustodyError):
        custody.recipient_public_b64()                     # tripwire: pub existe, privada nao
    with pytest.raises(custody.CustodyError):
        custody.recipient_private_bytes()
    assert not os.path.exists(custody._recipient_path())   # nada de chave nova em claro
    os.rename(custody._recipient_vault_path() + ".bak", custody._recipient_vault_path())
    assert custody.unlock_recipient("senha-x")
    assert custody.recipient_fingerprint() == fp           # restaurar o backup devolve a identidade


def test_rt_l1_pub_adulterada_e_detectada_no_unlock(tmp_identity):
    """L1: adulterar a publica em claro faz voce selar para OUTRA chave. Destravar detecta a
    divergencia (para a UI avisar) e re-amarra a publica correta."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import base64
    real_pub = custody.recipient_public_b64()
    custody.protect_recipient("senha-x")
    custody.lock_recipient()
    atacante = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with open(custody._recipient_pub_path(), "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(atacante).decode() + "\n")
    assert custody.recipient_public_b64() != real_pub       # travada, a mentira passa (documentado)
    assert custody.unlock_recipient("senha-x")
    assert custody.recipient_pub_was_divergent()           # DETECTADO
    assert custody.recipient_public_b64() == real_pub       # e corrigido
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")
    assert not custody.recipient_pub_was_divergent()       # agora bate: sem alarme falso


def test_rt_f4_detecta_copia_em_claro_orfa(tmp_identity):
    """F4: estado misto (cofre + raw) precisa ser DETECTAVEL para a UI avisar."""
    raw = custody.recipient_private_bytes()
    custody.protect_recipient("senha-x")
    assert not custody.recipient_has_orphan_raw()
    with open(custody._recipient_path(), "wb") as fh:      # residuo de proteger interrompido
        fh.write(raw)
    assert custody.recipient_has_orphan_raw()
    custody.lock_recipient()
    assert custody.unlock_recipient("senha-x")
    assert not custody.recipient_has_orphan_raw()          # curado no unlock


def test_rt_f10_add_unlocker_recusa_cofre_que_nao_e_chave(tmp_identity):
    """F10: um recipient.rdbt cujo conteudo NAO e chave X25519 nao pode ser aceito em silencio."""
    custody._atomic_write(custody._recipient_vault_path(),
                          vault.new_vault("isto nao e uma chave", password="senha-x"))
    assert custody.recipient_is_protected()
    with pytest.raises(vault.VaultError):
        custody.add_recipient_unlocker(passphrase="senha-x", new_password="backup")
    assert custody.unlock_recipient("senha-x") is False    # unlock tambem recusa (nao e chave)


def test_rt_recipient_unlockers_lista_tipos(tmp_identity):
    assert custody.recipient_unlockers() == []             # em claro: nenhum destravador
    custody.protect_recipient("senha-x")
    assert vault.KIND_PASSWORD in custody.recipient_unlockers()


def test_rt_f3_tripwire_usa_conjunto_de_evidencias(tmp_identity):
    """F3 (3a rodada): a tripwire olhava UM arquivo (recipient.pub). Bastava o AV comer o arquivo
    certo — deixando so o `.tmp` — para o app cunhar outra identidade em silencio."""
    custody.recipient_public_b64()
    fp = custody.recipient_fingerprint()
    os.rename(custody._recipient_pub_path(), custody._recipient_pub_path() + ".tmp")
    os.remove(custody._recipient_path())                   # so o vestigio .tmp sobrou
    custody.lock_recipient()
    with pytest.raises(custody.CustodyError):
        custody.recipient_public_b64()                     # nao inventa chave nova
    with pytest.raises(custody.CustodyError):
        custody.protect_recipient("senha-x")
    assert not custody.recipient_is_protected()
    assert not os.path.exists(custody._recipient_path())
    assert fp                                              # (identidade antiga segue sendo a unica)


def test_rt_sessao_viva_nunca_e_substituida(tmp_identity):
    """F3: a chave VIVA na sessao tem de mandar — antes o teste da sessao estava aninhado sob
    `recipient_is_protected()`, entao sem o .rdbt o app cunhava outra chave por cima."""
    custody.protect_recipient("senha-x")
    priv = custody.recipient_private_bytes()
    os.remove(custody._recipient_vault_path())             # cofre em quarentena, sessao viva
    assert custody.recipient_private_bytes() == priv       # mesma chave, nao uma nova


# --------------------------------------------------------------------------- #
# Mesmo defeito no GEMEO Ed25519 (identidade que assina a custodia) — CRITICO:
# alcancavel pelo menu "Proteger identidade com senha".
# --------------------------------------------------------------------------- #
def test_rt_protect_identity_pem_travado_nao_perde_a_identidade(tmp_identity, monkeypatch):
    """CRITICO: com o PEM travado (lock de AV), o rollback antigo apagava o cofre DEPOIS do wipe —
    a identidade Ed25519 ficava IRRECUPERAVEL e a trilha de custodia morria em silencio."""
    fp = custody.fingerprint()
    real_remove = os.remove
    monkeypatch.setattr(custody.os, "remove", _remove_travado_em([custody._pem_path()]))
    with pytest.raises(custody.IdentityClearCopyRemains):
        custody.protect_identity("senha-id")
    assert custody.is_protected()                          # o cofre PROVADO permanece
    assert custody.identity_has_orphan_pem()               # residuo em claro DETECTADO
    custody.lock_identity()
    assert custody.unlock_identity("senha-id")            # a identidade NAO se perdeu
    assert custody.fingerprint() == fp                     # e e a MESMA
    monkeypatch.setattr(custody.os, "remove", real_remove)
    custody.lock_identity()
    assert custody.unlock_identity("senha-id")
    assert not custody.identity_has_orphan_pem()          # curado no unlock
    assert custody.verify("msg", custody.sign("msg"))      # e continua assinando


def test_rt_unprotect_identity_cofre_travado_nao_perde_a_identidade(tmp_identity, monkeypatch):
    """CRITICO (espelho): unprotect sobrescrevia o cofre e depois apagava o PEM = perda TOTAL."""
    custody.protect_identity("senha-id")
    fp = custody.fingerprint()
    real_remove = os.remove                                # captura ANTES do patch
    monkeypatch.setattr(custody.os, "remove", _remove_travado_em([custody._vault_path()]))
    with pytest.raises(vault.VaultError):
        custody.unprotect_identity("senha-id")
    monkeypatch.setattr(custody.os, "remove", real_remove)
    assert custody.is_protected()                          # segue protegida
    custody.lock_identity()
    assert custody.unlock_identity("senha-id")            # cofre NAO foi corrompido
    assert custody.fingerprint() == fp


def test_rt_audit_log_nao_utf8_nao_derruba(tmp_identity):
    """Um unico byte nao-UTF8 na trilha levantava UnicodeDecodeError — que nao e OSError, escapava
    dos leitores e ABORTAVA o processo justamente em 'Verificar custodia'."""
    custody.log_event("abriu", "a.txt", "h1")
    with open(custody._audit_path(), "ab") as fh:
        fh.write(b"\xff\xfe lixo binario\n")
    entradas = custody.read_audit()                        # nao explode
    assert len(entradas) >= 1                              # a linha suja e descartada
    assert custody.verify_chain()[0]                       # e a cadeia segue verificavel
    assert custody.audit_stats()["total"] >= 1
