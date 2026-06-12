"""Testes do manifesto de release assinado (notepy/release.py) + o verificador
standalone (verify_release.py). Puro Python, sem Qt: usa a identidade Ed25519 real
do custody apontada para um diretorio temporario.

Inclui os casos de seguranca confirmados pelo red-team: re-assinatura por outra
chave, fingerprint forjado, entrada malformada (sem crash) e path traversal."""

import hashlib
import importlib.util
import json
import os

import pytest

from notepy import custody, release


@pytest.fixture
def ident(tmp_path, monkeypatch):
    iddir = tmp_path / "id"
    iddir.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(iddir))
    return tmp_path


def _make_dist(tmp_path, files):
    dist = tmp_path / "dist"
    dist.mkdir()
    for name, data in files.items():
        (dist / name).write_bytes(data)
    return str(dist)


def _manifest(dist, names, version="1.0.0", date="2026-06-12"):
    arts = release.scan_artifacts(dist, names)
    return release.build_manifest(
        product="Redoubt", version=version, date=date,
        public_key_b64=custody.public_key_b64(), fingerprint=custody.fingerprint(),
        artifacts=arts, sign_fn=custody.sign)


def _signed_manifest(payload_dict):
    """Monta um manifesto assinado pela identidade atual a partir de um payload arbitrario."""
    signed = release.canonical_payload(payload_dict)
    return {"format": "RDBT-REL1", "algorithm": "ed25519",
            "signed_payload": signed, "signature": custody.sign(signed)}


def _load_standalone():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "verify_release.py")
    spec = importlib.util.spec_from_file_location("verify_release_standalone", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# Roundtrip, integridade vs autenticidade
# --------------------------------------------------------------------------- #
def test_roundtrip_autentico(ident, tmp_path):
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"binario A",
                                 "Redoubt-Setup-1.0.0.exe": b"instalador B"})
    man = _manifest(dist, ["Redoubt.exe", "Redoubt-Setup-1.0.0.exe"])
    r = release.verify_manifest(man, dist, expect_fingerprint=custody.fingerprint())
    assert r["ok"] and r["signature_ok"] and r["integrity_ok"] and r["authentic"]
    assert r["fingerprint"] == custody.fingerprint()
    assert all(a["ok"] for a in r["artifacts"])


def test_integridade_ok_mas_sem_autenticidade(ident, tmp_path):
    """Sem expect_fingerprint: integridade pode passar, mas NUNCA declara 'autentico'."""
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    man = _manifest(dist, ["Redoubt.exe"])
    r = release.verify_manifest(man, dist)            # sem ancora
    assert r["integrity_ok"] is True
    assert r["authentic"] is None
    assert r["ok"] is False                            # nao confirma autenticidade


def test_fingerprint_derivado_da_chave(ident, tmp_path):
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    man = _manifest(dist, ["Redoubt.exe"])
    r = release.verify_manifest(man, dist)
    # o fingerprint reportado e DERIVADO da chave, igual ao do custody
    assert r["fingerprint"] == release.derive_fingerprint(custody.public_key_b64())
    assert r["fingerprint"] == custody.fingerprint()


# --------------------------------------------------------------------------- #
# Adulteracoes de integridade
# --------------------------------------------------------------------------- #
def test_arquivo_adulterado_apos_assinar_falha(ident, tmp_path):
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"original"})
    man = _manifest(dist, ["Redoubt.exe"])
    (tmp_path / "dist" / "Redoubt.exe").write_bytes(b"binario malicioso!")
    r = release.verify_manifest(man, dist, expect_fingerprint=custody.fingerprint())
    assert r["signature_ok"]
    assert r["artifacts"][0]["ok"] is False
    assert r["integrity_ok"] is False and r["ok"] is False


def test_trocar_hash_no_payload_quebra_assinatura(ident, tmp_path):
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    man = _manifest(dist, ["Redoubt.exe"])
    payload = json.loads(man["signed_payload"])
    payload["artifacts"][0]["sha256"] = "00" * 32
    man["signed_payload"] = release.canonical_payload(payload)
    r = release.verify_manifest(man, dist, expect_fingerprint=custody.fingerprint())
    assert not r["signature_ok"] and not r["ok"]


def test_assinatura_corrompida_falha(ident, tmp_path):
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    man = _manifest(dist, ["Redoubt.exe"])
    man["signature"] = "QU0naoEhBase64Valida=="
    r = release.verify_manifest(man, dist, expect_fingerprint=custody.fingerprint())
    assert not r["signature_ok"] and not r["ok"]


def test_artefato_ausente_falha(ident, tmp_path):
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    man = _manifest(dist, ["Redoubt.exe"])
    os.remove(os.path.join(dist, "Redoubt.exe"))
    r = release.verify_manifest(man, dist, expect_fingerprint=custody.fingerprint())
    assert r["artifacts"][0]["present"] is False and not r["ok"]


def test_fingerprint_esperado_certo_e_errado(ident, tmp_path):
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    man = _manifest(dist, ["Redoubt.exe"])
    assert release.verify_manifest(man, dist, expect_fingerprint="deadbeefdeadbeef")["authentic"] is False
    assert release.verify_manifest(man, dist, expect_fingerprint="deadbeefdeadbeef")["ok"] is False
    good = release.verify_manifest(man, dist, expect_fingerprint=custody.fingerprint())
    assert good["authentic"] and good["ok"]


def test_expect_pubkey_autenticacao_forte(tmp_path, monkeypatch):
    """expect_pubkey liga aos 32 bytes da chave: a chave certa autentica, a de outro nao."""
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "A"))
    (tmp_path / "A").mkdir()
    man = _manifest(dist, ["Redoubt.exe"])              # assinado por A
    pub_a = custody.public_key_b64()
    r_ok = release.verify_manifest(man, dist, expect_pubkey=pub_a)
    assert r_ok["authentic"] is True and r_ok["ok"] is True
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "B"))
    (tmp_path / "B").mkdir()
    pub_b = custody.public_key_b64()
    r_bad = release.verify_manifest(man, dist, expect_pubkey=pub_b)
    assert r_bad["authentic"] is False and r_bad["ok"] is False


# --------------------------------------------------------------------------- #
# SEGURANCA (red-team): re-assinatura, fingerprint forjado/inconsistente
# --------------------------------------------------------------------------- #
def test_reassinatura_por_outra_chave_declarando_fp_alheio_e_rejeitada(tmp_path, monkeypatch):
    """Achado critico: atacante assina com a propria chave mas DECLARA o fingerprint do autor."""
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"malware"})
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "A"))
    (tmp_path / "A").mkdir()
    fp_autor = custody.fingerprint()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(tmp_path / "B"))  # atacante
    (tmp_path / "B").mkdir()
    arts = release.scan_artifacts(dist, ["Redoubt.exe"])
    payload = {"product": "Redoubt", "version": "1.0.0", "date": "2026-06-12",
               "public_key": custody.public_key_b64(),   # chave do ATACANTE (B)
               "fingerprint": fp_autor,                  # MENTIRA: declara o fp do autor (A)
               "artifacts": arts}
    man = _signed_manifest(payload)                       # assinado por B
    r = release.verify_manifest(man, dist, expect_fingerprint=fp_autor)
    assert r["signature_ok"]                  # assinatura de B e valida SOB a chave de B
    assert r["fingerprint"] != fp_autor       # mas o derivado e o fp de B, nao de A
    assert r["fingerprint_declared_ok"] is False
    assert r["authentic"] is False
    assert r["ok"] is False                    # BARRADO


def test_campo_fingerprint_inconsistente_falha_integridade(ident, tmp_path):
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    arts = release.scan_artifacts(dist, ["Redoubt.exe"])
    payload = {"product": "R", "version": "1", "date": "d",
               "public_key": custody.public_key_b64(), "fingerprint": "0" * 16,  # mentira
               "artifacts": arts}
    man = _signed_manifest(payload)
    r = release.verify_manifest(man, dist, expect_fingerprint=custody.fingerprint())
    assert r["signature_ok"]
    assert r["fingerprint_declared_ok"] is False
    assert r["integrity_ok"] is False and r["ok"] is False


# --------------------------------------------------------------------------- #
# SEGURANCA (red-team): robustez — sem crash, sem traversal
# --------------------------------------------------------------------------- #
def test_artifacts_nao_lista_nao_crasha(ident, tmp_path):
    payload = {"product": "R", "version": "1", "date": "d",
               "public_key": custody.public_key_b64(), "fingerprint": custody.fingerprint(),
               "artifacts": "isto-nao-e-lista"}
    man = _signed_manifest(payload)
    r = release.verify_manifest(man, str(tmp_path), expect_fingerprint=custody.fingerprint())
    assert r["error"] is not None and r["ok"] is False   # tratado, nao crash


def test_artifact_item_nao_dict_nao_crasha(ident, tmp_path):
    payload = {"product": "R", "version": "1", "date": "d",
               "public_key": custody.public_key_b64(), "fingerprint": custody.fingerprint(),
               "artifacts": [123, "Redoubt.exe", None]}
    man = _signed_manifest(payload)
    r = release.verify_manifest(man, str(tmp_path), expect_fingerprint=custody.fingerprint())
    assert r["error"] is None                            # nao crashou
    assert any(a.get("invalid") is not None for a in r["artifacts"])
    assert r["ok"] is False


def test_path_traversal_no_name_rejeitado(ident, tmp_path):
    (tmp_path / "secret.bin").write_bytes(b"conteudo fora do dist")
    dist = tmp_path / "dist"
    dist.mkdir()
    h = hashlib.sha256(b"conteudo fora do dist").hexdigest()
    payload = {"product": "R", "version": "1", "date": "d",
               "public_key": custody.public_key_b64(), "fingerprint": custody.fingerprint(),
               "artifacts": [{"name": "../secret.bin", "sha256": h, "size": 21}]}
    man = _signed_manifest(payload)
    r = release.verify_manifest(man, str(dist), expect_fingerprint=custody.fingerprint())
    assert r["artifacts"][0].get("unsafe") is True       # nome com '..' rejeitado
    assert r["ok"] is False                               # nao validou via traversal


def test_nome_absoluto_rejeitado(ident, tmp_path):
    payload = {"product": "R", "version": "1", "date": "d",
               "public_key": custody.public_key_b64(), "fingerprint": custody.fingerprint(),
               "artifacts": [{"name": "C:\\Windows\\system32\\x.dll", "sha256": "00", "size": 1}]}
    man = _signed_manifest(payload)
    r = release.verify_manifest(man, str(tmp_path), expect_fingerprint=custody.fingerprint())
    assert r["artifacts"][0].get("unsafe") is True and not r["ok"]


# --------------------------------------------------------------------------- #
# Geracao e malformados
# --------------------------------------------------------------------------- #
def test_sha256sums_formato(ident, tmp_path):
    arts = [{"name": "b.exe", "sha256": "aa", "size": 1},
            {"name": "a.exe", "sha256": "bb", "size": 2}]
    assert release.sha256sums_text(arts) == "bb  a.exe\naa  b.exe\n"


def test_manifesto_malformado_nao_crasha(tmp_path):
    assert release.verify_manifest({}, str(tmp_path))["error"]
    assert release.verify_manifest({"signed_payload": "{lixo", "signature": "x"},
                                   str(tmp_path))["error"]
    assert release.verify_manifest({"signed_payload": "[]", "signature": "x"},
                                   str(tmp_path))["error"]  # payload nao-objeto


def test_scan_artifacts_erra_se_faltar(ident, tmp_path):
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    with pytest.raises(FileNotFoundError):
        release.scan_artifacts(dist, ["Redoubt.exe", "naoexiste.exe"])


# --------------------------------------------------------------------------- #
# Verificador STANDALONE: ancora embutida + consistencia com o nucleo
# --------------------------------------------------------------------------- #
def test_standalone_concorda_com_nucleo(ident, tmp_path):
    vr = _load_standalone()
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"abc", "Redoubt-Setup-1.0.0.exe": b"def"})
    man = _manifest(dist, ["Redoubt.exe", "Redoubt-Setup-1.0.0.exe"])
    with open(os.path.join(dist, "RELEASE.json"), "w", encoding="utf-8") as fh:
        json.dump(man, fh)
    # ancora = a chave de teste (a embutida e a real do autor, que nao assinou aqui)
    ok, _ = vr.verify_dir(dist, trust_pubkey=custody.public_key_b64())
    assert ok is True
    assert release.verify_manifest(man, dist, expect_fingerprint=custody.fingerprint())["ok"] is True
    (tmp_path / "dist" / "Redoubt.exe").write_bytes(b"ADULTERADO")
    ok2, _ = vr.verify_dir(dist, trust_pubkey=custody.public_key_b64())
    assert ok2 is False


def test_standalone_rejeita_chave_nao_autoral(ident, tmp_path):
    """A ancora embutida (chave real do autor) rejeita manifesto assinado por outra chave."""
    vr = _load_standalone()
    dist = _make_dist(tmp_path, {"Redoubt.exe": b"x"})
    man = _manifest(dist, ["Redoubt.exe"])               # assinado pela chave de TESTE
    with open(os.path.join(dist, "RELEASE.json"), "w", encoding="utf-8") as fh:
        json.dump(man, fh)
    ok_default, _ = vr.verify_dir(dist)                  # usa AUTHOR_PUBKEY_B64 embutida
    assert ok_default is False                            # chave de teste != ancora do autor
    ok_certo, _ = vr.verify_dir(dist, trust_pubkey=custody.public_key_b64())
    assert ok_certo is True


def test_standalone_fingerprint_derivado(ident, tmp_path):
    vr = _load_standalone()
    assert vr.fingerprint_of(custody.public_key_b64()) == custody.fingerprint()
    assert vr.AUTHOR_FINGERPRINT == vr.fingerprint_of(vr.AUTHOR_PUBKEY_B64)
