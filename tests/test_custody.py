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
    """Zera o cache de sessao da chave entre testes (e um global do modulo)."""
    custody.lock_identity()
    yield
    custody.lock_identity()


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
def test_pem_orfao_faz_rollback(tmp_identity, monkeypatch):
    """Se a remocao do PEM em claro falhar, protect_identity faz ROLLBACK e NAO reporta sucesso."""
    custody.sign("x")                                   # cria a identidade legada (PEM existe)
    monkeypatch.setattr(custody, "_secure_remove", lambda p: None)   # simula remocao que falhou
    with pytest.raises(vault.VaultError):
        custody.protect_identity("pw")
    assert os.path.exists(custody._pem_path())          # PEM em claro ainda la...
    assert not custody.is_protected()                   # ...e o cofre foi desfeito (rollback)


def test_unprotect_orfao_faz_rollback(tmp_identity, monkeypatch):
    """Espelho: se remover o cofre falhar no unprotect, desfaz o PEM e mantem protegido."""
    custody.sign("x")
    custody.protect_identity("pw")
    real = custody._secure_remove
    def fake(path):
        if path == custody._vault_path():
            raise OSError("locked")                     # remocao do cofre falha
        return real(path)                               # rollback do PEM funciona
    monkeypatch.setattr(custody, "_secure_remove", fake)
    with pytest.raises(vault.VaultError):
        custody.unprotect_identity("pw")
    assert custody.is_protected()                       # continua protegido (cofre ficou)
    assert not os.path.exists(custody._pem_path())      # PEM em claro desfeito (rollback)


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
