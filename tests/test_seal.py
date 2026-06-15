"""Testes do selo de proveniencia (notepy/seal.py) + o verificador standalone
(verify_seal.py). Puro Python, sem Qt: usa a identidade Ed25519 real do custody
apontada para um diretorio temporario.

Inclui os casos de seguranca do red-team: re-assinatura por outra chave, fingerprint
forjado, SUBSTITUICAO de selo (selo de um arquivo colado em outro), nome inerte
(sem path traversal), trilha assinada e entrada malformada (sem crash)."""

import hashlib
import importlib.util
import json
import os

import pytest

from notepy import custody, seal


@pytest.fixture(autouse=True)
def _reset_identity_cache():
    custody.lock_identity()
    yield
    custody.lock_identity()


@pytest.fixture
def ident(tmp_path, monkeypatch):
    iddir = tmp_path / "id"
    iddir.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(iddir))
    return tmp_path


def _file(tmp_path, name="evidencia.txt", data=b"conteudo selavel\n"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _seal(path, sealed_at="2026-06-15T00:00:00+00:00", trail=None):
    """Sela `path` com a identidade atual (a do diretorio temporario do fixture)."""
    return seal.seal_file(path, sign_fn=custody.sign,
                          public_key_b64=custody.public_key_b64(),
                          fingerprint=custody.fingerprint(),
                          sealed_at=sealed_at, trail=trail)


def _signed_seal(payload_dict):
    """Monta um selo assinado pela identidade atual a partir de um payload arbitrario."""
    signed = seal.canonical_payload(payload_dict)
    return {"format": "RDBT-SEAL1", "algorithm": "ed25519",
            "signed_payload": signed, "signature": custody.sign(signed)}


def _load_standalone():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "verify_seal.py")
    spec = importlib.util.spec_from_file_location("verify_seal_standalone", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# Roundtrip, integridade vs autenticidade
# --------------------------------------------------------------------------- #
def test_roundtrip_autentico(ident, tmp_path):
    f = _file(tmp_path)
    s = _seal(f)
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert r["ok"] and r["signature_ok"] and r["integrity_ok"] and r["authentic"]
    assert r["content_ok"] and r["size_ok"] and r["name_match"]
    assert r["fingerprint"] == custody.fingerprint()
    assert r["fingerprint_declared_ok"] is True


def test_integridade_sem_autenticidade(ident, tmp_path):
    """Sem expect_*: integridade pode passar, mas NUNCA declara 'autentico'."""
    f = _file(tmp_path)
    s = _seal(f)
    r = seal.verify_seal(s, f)
    assert r["integrity_ok"] is True
    assert r["authentic"] is None
    assert r["ok"] is False


def test_fingerprint_derivado_da_chave(ident, tmp_path):
    f = _file(tmp_path)
    r = seal.verify_seal(_seal(f), f)
    assert r["fingerprint"] == seal.derive_fingerprint(custody.public_key_b64())
    assert r["fingerprint"] == custody.fingerprint()


def test_expect_pubkey_autenticacao_forte(tmp_path, monkeypatch):
    f = _file(tmp_path)
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "A"))
    (tmp_path / "A").mkdir()
    s = _seal(f)                                   # assinado por A
    pub_a = custody.public_key_b64()
    r_ok = seal.verify_seal(s, f, expect_pubkey=pub_a)
    assert r_ok["authentic"] is True and r_ok["ok"] is True
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "B"))
    (tmp_path / "B").mkdir()
    pub_b = custody.public_key_b64()
    r_bad = seal.verify_seal(s, f, expect_pubkey=pub_b)
    assert r_bad["authentic"] is False and r_bad["ok"] is False


def test_expect_fingerprint_certo_e_errado(ident, tmp_path):
    f = _file(tmp_path)
    s = _seal(f)
    assert seal.verify_seal(s, f, expect_fingerprint="deadbeefdeadbeef")["ok"] is False
    good = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert good["authentic"] and good["ok"]


# --------------------------------------------------------------------------- #
# Integridade — adulteracoes
# --------------------------------------------------------------------------- #
def test_conteudo_adulterado_falha(ident, tmp_path):
    f = _file(tmp_path)
    s = _seal(f)
    (tmp_path / "evidencia.txt").write_bytes(b"conteudo ADULTERADO\n")
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert r["signature_ok"]                 # a assinatura cobre o payload original
    assert r["content_ok"] is False           # mas o conteudo nao bate mais
    assert r["integrity_ok"] is False and r["ok"] is False


def test_trocar_sha_no_payload_quebra_assinatura(ident, tmp_path):
    f = _file(tmp_path)
    s = _seal(f)
    payload = json.loads(s["signed_payload"])
    payload["sha256"] = "00" * 32
    s["signed_payload"] = seal.canonical_payload(payload)
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert not r["signature_ok"] and not r["ok"]


def test_assinatura_corrompida_falha(ident, tmp_path):
    f = _file(tmp_path)
    s = _seal(f)
    s["signature"] = "QU0naoEhBase64Valida=="
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert not r["signature_ok"] and not r["ok"]


def test_arquivo_ausente_falha(ident, tmp_path):
    f = _file(tmp_path)
    s = _seal(f)
    os.remove(f)
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert r["present"] is False and r["content_ok"] is False and r["ok"] is False


# --------------------------------------------------------------------------- #
# SEGURANCA (red-team): substituicao, re-assinatura, fingerprint forjado
# --------------------------------------------------------------------------- #
def test_substituicao_selo_de_outro_arquivo_rejeitada(ident, tmp_path):
    """O selo de A nao valida o conteudo de B — mesmo com o mesmo nome (anti-substituicao)."""
    a = _file(tmp_path, "doc.txt", b"conteudo verdadeiro\n")
    s = _seal(a)
    # B tem o MESMO nome em outra pasta, mas conteudo diferente
    other = tmp_path / "outra"
    other.mkdir()
    b = other / "doc.txt"
    b.write_bytes(b"conteudo FALSIFICADO\n")
    r = seal.verify_seal(s, str(b), expect_fingerprint=custody.fingerprint())
    assert r["name_match"] is True            # mesmo nome
    assert r["content_ok"] is False            # mas o hash nao bate
    assert r["ok"] is False


def test_renomear_nao_quebra_pois_amarra_e_o_conteudo(ident, tmp_path):
    """Renomear o arquivo: o conteudo e identico, entao o selo confere (name e informativo)."""
    a = _file(tmp_path, "original.txt", b"bytes identicos\n")
    s = _seal(a)
    renamed = tmp_path / "renomeado.txt"
    renamed.write_bytes(b"bytes identicos\n")
    r = seal.verify_seal(s, str(renamed), expect_fingerprint=custody.fingerprint())
    assert r["content_ok"] is True
    assert r["name_match"] is False            # nome diferente
    assert r["declared_name"] == "original.txt"
    assert r["ok"] is True                      # o conteudo e a amarra forte


def test_reassinatura_por_outra_chave_declarando_fp_alheio_rejeitada(tmp_path, monkeypatch):
    """Atacante sela com a propria chave mas DECLARA o fingerprint do autor."""
    f = _file(tmp_path, "doc.txt", b"malware\n")
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "A"))
    (tmp_path / "A").mkdir()
    fp_autor = custody.fingerprint()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "B"))  # atacante
    (tmp_path / "B").mkdir()
    payload = seal.build_payload(
        name="doc.txt", sha256=hashlib.sha256(b"malware\n").hexdigest(), size=8,
        sealed_at="2026-06-15T00:00:00+00:00",
        public_key_b64=custody.public_key_b64(),   # chave do ATACANTE (B)
        fingerprint=fp_autor,                       # MENTIRA: declara o fp do autor (A)
        trail=None)
    s = _signed_seal(payload)                       # assinado por B
    r = seal.verify_seal(s, f, expect_fingerprint=fp_autor)
    assert r["signature_ok"]                  # valida SOB a chave de B
    assert r["fingerprint"] != fp_autor       # derivado = fp de B
    assert r["fingerprint_declared_ok"] is False
    assert r["authentic"] is False and r["ok"] is False   # BARRADO


def test_campo_fingerprint_inconsistente_falha_integridade(ident, tmp_path):
    f = _file(tmp_path)
    payload = seal.build_payload(
        name="evidencia.txt", sha256=hashlib.sha256(b"conteudo selavel\n").hexdigest(),
        size=17, sealed_at="t", public_key_b64=custody.public_key_b64(),
        fingerprint="0" * 16, trail=None)            # fingerprint mentido
    s = _signed_seal(payload)
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert r["signature_ok"]
    assert r["fingerprint_declared_ok"] is False
    assert r["integrity_ok"] is False and r["ok"] is False


# --------------------------------------------------------------------------- #
# SEGURANCA (red-team): trilha assinada, nome inerte, robustez
# --------------------------------------------------------------------------- #
def test_trilha_e_assinada_nao_adulteravel(ident, tmp_path):
    f = _file(tmp_path)
    s = _seal(f, trail={"seq": 5, "head_hash": "a" * 64})
    assert seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())["trail"] == {
        "seq": 5, "head_hash": "a" * 64}
    payload = json.loads(s["signed_payload"])
    payload["trail"]["seq"] = 999                    # adultera a trilha assinada
    s["signed_payload"] = seal.canonical_payload(payload)
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert r["signature_ok"] is False and r["ok"] is False   # assinatura quebra


def test_nome_no_selo_nunca_vira_caminho(ident, tmp_path):
    """O 'name' do selo e inerte: verify_seal so le o file_path dado, nunca o nome declarado."""
    f = _file(tmp_path, "real.txt", b"abc\n")
    payload = seal.build_payload(
        name="../../../etc/passwd", sha256=hashlib.sha256(b"abc\n").hexdigest(), size=4,
        sealed_at="t", public_key_b64=custody.public_key_b64(),
        fingerprint=custody.fingerprint(), trail=None)
    s = _signed_seal(payload)
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert r["content_ok"] is True             # leu o file_path real, nao o nome malicioso
    assert r["declared_name"] == "../../../etc/passwd"
    assert r["name_match"] is False
    assert r["ok"] is True                      # o nome nao afeta a verificacao do conteudo


def test_selo_malformado_nao_crasha(ident, tmp_path):
    f = _file(tmp_path)
    assert seal.verify_seal({}, f)["error"]
    assert seal.verify_seal({"signed_payload": "{lixo", "signature": "x"}, f)["error"]
    assert seal.verify_seal({"signed_payload": "[]", "signature": "x"}, f)["error"]  # nao-objeto


def test_public_key_invalida_nao_crasha(ident, tmp_path):
    f = _file(tmp_path)
    payload = {"format": "RDBT-SEAL1", "name": "x", "sha256": "00", "size": 1,
               "sealed_at": "t", "public_key": "@@@nao-base64@@@", "fingerprint": "x",
               "trail": None}
    s = _signed_seal(payload)
    r = seal.verify_seal(s, f)
    assert r["error"] is not None and r["ok"] is False


def test_public_key_nao_string_nao_crasha(ident, tmp_path):
    f = _file(tmp_path)
    s = _signed_seal({"format": "RDBT-SEAL1", "name": "x", "sha256": "00", "size": 1,
                      "sealed_at": "t", "public_key": 12345, "fingerprint": "x", "trail": None})
    r = seal.verify_seal(s, f)
    assert r["error"] is not None and r["ok"] is False


# --------------------------------------------------------------------------- #
# current_trail: snapshot read-only do head da trilha
# --------------------------------------------------------------------------- #
def test_current_trail_none_quando_vazia(ident, tmp_path):
    assert seal.current_trail() is None


def test_current_trail_reflete_o_head(ident, tmp_path):
    custody.log_event("abrir", "x")
    e2 = custody.log_event("salvar", "y")
    t = seal.current_trail()
    assert t["seq"] == 2 and t["head_hash"] == e2["hash"]


# --------------------------------------------------------------------------- #
# Verificador STANDALONE: ancora embutida + consistencia com o nucleo
# --------------------------------------------------------------------------- #
def test_standalone_concorda_com_nucleo(ident, tmp_path):
    vr = _load_standalone()
    f = _file(tmp_path)
    s = _seal(f)
    with open(f + ".rdbt-seal", "w", encoding="utf-8") as fh:
        json.dump(s, fh)
    ok, _ = vr.verify_file(f, trust_pubkey=custody.public_key_b64())
    assert ok is True
    assert seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())["ok"] is True
    (tmp_path / "evidencia.txt").write_bytes(b"ADULTERADO")
    ok2, _ = vr.verify_file(f, trust_pubkey=custody.public_key_b64())
    assert ok2 is False


def test_standalone_rejeita_chave_nao_autoral(ident, tmp_path):
    """A ancora embutida (chave real do autor) rejeita selo assinado por outra chave."""
    vr = _load_standalone()
    f = _file(tmp_path)
    s = _seal(f)
    with open(f + ".rdbt-seal", "w", encoding="utf-8") as fh:
        json.dump(s, fh)
    ok_default, _ = vr.verify_file(f)                  # usa AUTHOR_PUBKEY_B64 embutida
    assert ok_default is False                          # chave de teste != ancora do autor
    ok_certo, _ = vr.verify_file(f, trust_pubkey=custody.public_key_b64())
    assert ok_certo is True


def test_standalone_fingerprint_derivado(ident, tmp_path):
    vr = _load_standalone()
    assert vr.fingerprint_of(custody.public_key_b64()) == custody.fingerprint()
    assert vr.AUTHOR_FINGERPRINT == vr.fingerprint_of(vr.AUTHOR_PUBKEY_B64)


def test_standalone_selo_malformado_nao_crasha(ident, tmp_path):
    vr = _load_standalone()
    f = _file(tmp_path)
    with open(f + ".rdbt-seal", "w", encoding="utf-8") as fh:
        fh.write("{ lixo nao json")
    ok, lines = vr.verify_file(f, trust_pubkey=custody.public_key_b64())
    assert ok is False and any("ERRO" in ln for ln in lines)


# --------------------------------------------------------------------------- #
# CLI:  python -m notepy.seal make|verify
# --------------------------------------------------------------------------- #
def test_cli_make_verify_roundtrip(ident, tmp_path, capsys):
    f = _file(tmp_path)
    assert seal.main(["make", f]) == 0
    assert os.path.isfile(f + ".rdbt-seal")
    capsys.readouterr()
    rc = seal.main(["verify", f, "--expect-fingerprint", custody.fingerprint()])
    out = capsys.readouterr().out
    assert rc == 0 and "INTEGRO E AUTENTICO" in out


def test_cli_make_registra_evento_na_trilha(ident, tmp_path, capsys):
    f = _file(tmp_path)
    seal.main(["make", f])
    capsys.readouterr()
    eventos = [e.get("event") for e in custody.read_audit()]
    assert "selou" in eventos


def test_cli_verify_conteudo_adulterado(ident, tmp_path, capsys):
    f = _file(tmp_path)
    seal.main(["make", f])
    (tmp_path / "evidencia.txt").write_bytes(b"mudou\n")
    capsys.readouterr()
    rc = seal.main(["verify", f, "--expect-fingerprint", custody.fingerprint()])
    out = capsys.readouterr().out
    assert rc == 1 and "NAO CONFIRMADO" in out


# --------------------------------------------------------------------------- #
# Pos red-team: trail nao-dict normalizado + leitura do alvo blindada (OSError)
# --------------------------------------------------------------------------- #
def _full_payload(trail):
    return seal.build_payload(
        name="evidencia.txt", sha256=hashlib.sha256(b"conteudo selavel\n").hexdigest(),
        size=17, sealed_at="t", public_key_b64=custody.public_key_b64(),
        fingerprint=custody.fingerprint(), trail=trail)


@pytest.mark.parametrize("trail", ["pwned", ["x"], 12345, True])
def test_trail_nao_dict_normalizado_para_none(ident, tmp_path, trail):
    """trail truthy NAO-dict no payload assinado e normalizado para None (so dict|None sai)."""
    f = _file(tmp_path)
    s = _signed_seal(_full_payload(trail))
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert r["trail"] is None
    assert r["ok"] is True                       # selo valido + conteudo confere; trail invalido ignorado


def test_cli_verify_trail_nao_dict_nao_crasha(ident, tmp_path, capsys):
    """Regressao do red-team: CLI nao pode crashar (AttributeError) com trail truthy nao-dict."""
    f = _file(tmp_path)
    s = _signed_seal(_full_payload("pwned"))
    with open(f + seal.SEAL_SUFFIX, "w", encoding="utf-8") as fh:
        json.dump(s, fh)
    capsys.readouterr()
    rc = seal.main(["verify", f, "--expect-fingerprint", custody.fingerprint()])  # nao deve levantar
    out = capsys.readouterr().out
    assert rc == 0 and "INTEGRO E AUTENTICO" in out


def test_oserror_no_alvo_nucleo_nao_crasha(ident, tmp_path, monkeypatch):
    """Regressao do red-team: leitura do alvo falhando (lock OneDrive/AV/TOCTOU) vira io_error, sem crash."""
    f = _file(tmp_path)
    s = _seal(f)

    def boom(_p):
        raise OSError("travado pelo OneDrive")
    monkeypatch.setattr(seal, "sha256_file", boom)
    r = seal.verify_seal(s, f, expect_fingerprint=custody.fingerprint())
    assert r["error"] is None                    # nao e "malformado", nao levantou
    assert r["present"] is True                   # o arquivo existe; so a leitura falhou
    assert r["io_error"] is not None
    assert r["content_ok"] is False and r["ok"] is False


def test_oserror_no_alvo_standalone_nao_crasha(ident, tmp_path, monkeypatch):
    vr = _load_standalone()
    f = _file(tmp_path)
    s = _seal(f)
    with open(f + ".rdbt-seal", "w", encoding="utf-8") as fh:
        json.dump(s, fh)

    def boom(_p):
        raise OSError("travado")
    monkeypatch.setattr(vr, "sha256_file", boom)
    ok, lines = vr.verify_file(f, trust_pubkey=custody.public_key_b64())
    assert ok is False
    assert any("nao consegui ler" in ln.lower() for ln in lines)


def test_cli_make_oserror_nao_crasha(ident, tmp_path, monkeypatch, capsys):
    """Regressao da re-confirmacao: `seal make` num arquivo travado da erro limpo, sem traceback."""
    f = _file(tmp_path)

    def boom(_p):
        raise OSError("travado ao selar")
    monkeypatch.setattr(seal, "sha256_file", boom)
    rc = seal.main(["make", f])                       # nao deve levantar
    out = capsys.readouterr().out
    assert rc == 2 and "falha de IO" in out
    assert not os.path.exists(f + seal.SEAL_SUFFIX)    # nao deixou selo parcial
