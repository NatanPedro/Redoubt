#!/usr/bin/env python3
"""Verificador standalone do release do Redoubt — rode SEM instalar o Redoubt.

Confere que os binarios que voce baixou sao AUTENTICOS e INTEGROS:
  1) AUTENTICIDADE: a assinatura Ed25519 do manifesto bate com a CHAVE PUBLICA DO AUTOR
     embutida abaixo (`AUTHOR_PUBKEY_B64`). Como este arquivo vem do repositorio oficial,
     a chave de confianca chega pelo mesmo canal — um atacante teria que possuir a chave
     PRIVADA do autor para forjar uma assinatura valida, o que e inviavel.
  2) INTEGRIDADE: o SHA-256 de cada artefato bate com o valor assinado.

Uso:
    python verify_release.py [DIR]                 # DIR com os .exe + RELEASE.json (default: .)
    python verify_release.py DIR --pubkey <b64>    # verificar release de OUTRO autor (chave por canal confiavel)

Unica dependencia externa: o pacote `cryptography`  (pip install cryptography).

Confirme que o fingerprint impresso e o publicado no repositorio oficial:
    github.com/NatanPedro/Redoubt
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    print("Falta a biblioteca 'cryptography'.  Instale com:  pip install cryptography")
    sys.exit(2)

# === Ancora de confianca: a chave publica do AUTOR oficial do Redoubt ========
# (32 bytes, base64). Vem versionada neste arquivo, pelo repositorio oficial.
# Chave ATUAL, desde a v1.4.0 (2026-09-24).
AUTHOR_PUBKEY_B64 = "jkPCODB0xP85HRf+U6l0WAfnKJlAvGuMB6HeN0Wg2Fs="
AUTHOR_FINGERPRINT = "6b38433243e8f7e7"   # = sha256(pubkey)[:16], so para exibir

# Chaves ANTERIORES do autor, APOSENTADAS. A 4e391f28930f3b6e assinou os releases ate a v1.3.0 e
# se perdeu junto com a maquina que a guardava (disco destruido: a chave nao vazou, so deixou de
# existir). Como nao assina mais nada, so vale para o que ja assinou: releases ate `max_version`.
# Um manifesto de versao posterior assinado por ela e recusado.
RETIRED_AUTHOR_KEYS = (
    {"pubkey": "RZZBbCP6irycPMcBLFs5raHw5gONJOU5LMYZwGawrBA=", "fingerprint": "4e391f28930f3b6e",
     "retired": "2026-09-24", "max_version": "1.3.0"},
)
# =============================================================================

MANIFEST_NAME = "RELEASE.json"
_BLOCK = 1 << 20


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_BLOCK), b""):
            h.update(chunk)
    return h.hexdigest()


def fingerprint_of(public_b64):
    """sha256(chave publica crua)[:16] — mesma formula da custodia do Redoubt."""
    return hashlib.sha256(base64.b64decode(public_b64, validate=True)).hexdigest()[:16]


def verify_signature(signed_payload, signature_b64, public_b64):
    """True se `signature_b64` for uma assinatura Ed25519 valida de `signed_payload` sob `public_b64`."""
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_b64, validate=True))
        pub.verify(sig, signed_payload.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def _is_safe_name(name):
    """Nome de artefato deve ser um nome de arquivo SIMPLES (sem separador, `..`, drive ou absoluto)."""
    return bool(
        isinstance(name, str) and name
        and name not in (".", "..")
        and not any(c in name for c in ("/", "\\", ":"))
        and not os.path.isabs(name)
    )


def _version_tuple(v):
    """'1.3.0' -> (1, 3, 0). None se nao for uma versao numerica simples."""
    if not isinstance(v, str):
        return None
    parts = v.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _trust_chain(trust_pubkey):
    """Chaves aceitas, em ordem: [(pubkey, metadados_se_aposentada)]. Com `--pubkey` explicito,
    SO ela (quem escolheu a ancora decide); sem, a chave atual do autor + as aposentadas."""
    if trust_pubkey is not None:
        return [(trust_pubkey, None)]
    return [(AUTHOR_PUBKEY_B64, None)] + [(k["pubkey"], k) for k in RETIRED_AUTHOR_KEYS]


def verify_dir(directory, manifest_path=None, trust_pubkey=None):
    """Verifica os binarios de `directory` contra a ancora de confianca.

    `trust_pubkey=None` (padrao) usa a chave do AUTOR embutida acima e aceita as chaves
    aposentadas apenas para as versoes que elas assinaram. Um `trust_pubkey` explicito vira a
    unica ancora. Retorna (ok: bool, linhas: list[str]). `ok` exige AUTENTICIDADE (assinatura
    valida sob uma chave de confianca aplicavel) E INTEGRIDADE (todos os artefatos presentes
    com hash batendo). Nunca levanta por entrada malformada.
    """
    mp = manifest_path or os.path.join(directory, MANIFEST_NAME)
    try:
        with open(mp, encoding="utf-8") as fh:
            manifest = json.load(fh)
        signed = manifest["signed_payload"]
        signature = manifest["signature"]
        if not isinstance(signed, str) or not isinstance(signature, str):
            raise ValueError("signed_payload/signature ausente ou nao-string")
        payload = json.loads(signed)
        if not isinstance(payload, dict):
            raise ValueError("signed_payload nao e um objeto JSON")
        artifacts = payload.get("artifacts", [])
        if not isinstance(artifacts, list):
            raise ValueError("artifacts deve ser uma lista")
        chain = _trust_chain(trust_pubkey)
        trust_fp = fingerprint_of(chain[0][0])   # valida a ancora
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, binascii.Error) as e:
        return False, [f"[ERRO] manifesto/ancora invalido ({mp}): {e}"]

    # 1) AUTENTICIDADE: a assinatura confere com uma CHAVE DE CONFIANCA (nunca a do payload).
    # Chave aposentada so vale ate a versao que ela assinou.
    authentic, retired, out_of_range = False, None, None
    version = payload.get("version")
    for pub, meta in chain:
        if not verify_signature(signed, signature, pub):
            continue
        if meta is not None:
            vt, maxv = _version_tuple(version), _version_tuple(meta["max_version"])
            if vt is None or maxv is None or vt > maxv:
                out_of_range = meta
                continue
        authentic, retired = True, meta
        trust_fp = fingerprint_of(pub)
        break
    out = [f"Chave de confianca (fingerprint): {trust_fp}"]
    if retired is not None:
        out.append(f"  (chave ANTERIOR do autor, aposentada em {retired['retired']}: vale para "
                   f"releases ate a v{retired['max_version']})")
    out.append(f"Assinatura confere com a chave do autor: {'SIM' if authentic else 'NAO'}")
    if out_of_range is not None:
        out.append(f"  (assinado pela chave APOSENTADA {out_of_range['fingerprint']}, que so vale ate a "
                   f"v{out_of_range['max_version']}; este manifesto declara a versao {version!r})")
    elif not authentic:
        declared = payload.get("public_key")
        if isinstance(declared, str):
            try:
                out.append(f"  (o manifesto foi assinado por OUTRA chave, fingerprint {fingerprint_of(declared)})")
            except (ValueError, binascii.Error):
                out.append("  (o manifesto declara uma chave publica invalida)")

    # 2) INTEGRIDADE: cada artefato presente e com hash batendo
    files_ok = True
    out.append("Artefatos:")
    for a in artifacts:
        if not isinstance(a, dict):
            out.append(f"  [ENTRADA INVALIDA] {a!r}")
            files_ok = False
            continue
        name = a.get("name")
        expected = a.get("sha256")
        if not _is_safe_name(name):
            out.append(f"  [NOME INSEGURO] {name!r}")
            files_ok = False
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            out.append(f"  [AUSENTE] {name}")
            files_ok = False
            continue
        ok = (sha256_file(path) == expected)
        files_ok = files_ok and ok
        out.append(f"  [{'OK' if ok else 'HASH NAO CONFERE'}] {name}")

    ok = bool(authentic and files_ok and artifacts)
    out += ["", f"Veredito: {'INTEGRO E AUTENTICO' if ok else 'FALHOU'}"]
    if ok:
        out.append(f"(Confirme que {trust_fp} e o fingerprint publicado no repositorio oficial.)")
    return ok, out


def main(argv=None):
    p = argparse.ArgumentParser(description="Verifica um release do Redoubt (standalone).")
    p.add_argument("dir", nargs="?", default=".",
                   help="diretorio com os binarios + RELEASE.json (default: atual)")
    p.add_argument("--manifest", default=None,
                   help="caminho do RELEASE.json (default: <dir>/RELEASE.json)")
    p.add_argument("--pubkey", default=None,
                   help="chave publica de confianca em base64 (default: a do autor oficial, "
                        "mais as chaves aposentadas para as versoes que elas assinaram)")
    args = p.parse_args(argv)
    ok, lines = verify_dir(args.dir, args.manifest, trust_pubkey=args.pubkey)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
