"""Manifesto de release assinado — o Redoubt prova a propria integridade.

Gera, ao lado dos binarios, um `RELEASE.json` assinado com a identidade Ed25519
do Redoubt (`notepy/custody.py`) + um `SHA256SUMS` no formato padrao. Qualquer um
verifica o download com `verify_release.py` (standalone, sem instalar o Redoubt)
ou com `python -m notepy.release verify <dir> --expect-fingerprint <fp>`.

Formato `RDBT-REL1`: o que importa e o **`signed_payload`** — uma STRING JSON canonica
com versao, data, chave publica, fingerprint e o sha256+tamanho de cada artefato. A
`signature` (Ed25519) cobre exatamente essa string. O verificador checa a assinatura
SOBRE A STRING e so entao a parseia para comparar os hashes — logo NAO precisa
reserializar JSON identicamente (zero divergencia entre gerador e verificador).

Modelo de confianca (importante, pos red-team):
- INTEGRIDADE = a assinatura e valida e os arquivos batem com os hashes assinados.
- AUTENTICIDADE = a chave que assinou e MESMO a do autor. A chave publica viaja dentro
  do payload (auto-assinado), entao a assinatura sozinha NAO prova autenticidade — um
  atacante re-assina tudo com a propria chave. Por isso:
    * o fingerprint e sempre DERIVADO da chave (`sha256(pubkey)[:16]`), nunca lido de um
      campo livre que o atacante controla;
    * `verify_manifest` so devolve `ok=True` quando o fingerprint DERIVADO bate com um
      `expect_fingerprint` fornecido por canal confiavel;
    * o `verify_release.py` standalone (que vem do repo oficial) EMBUTE a chave publica
      do autor e valida a assinatura contra ela.
Nucleo puro: sem Qt, sem rede; a assinatura e injetada (`sign_fn`).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST_NAME = "RELEASE.json"
SUMS_NAME = "SHA256SUMS"
FORMAT = "RDBT-REL1"
_BLOCK = 1 << 20  # 1 MiB por leitura


# --------------------------------------------------------------------------- #
# Hash, fingerprint, nome seguro, serializacao canonica
# --------------------------------------------------------------------------- #
def sha256_file(path: str) -> str:
    """SHA-256 (hex) de um arquivo, lido em blocos (aguenta binario grande)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_BLOCK), b""):
            h.update(chunk)
    return h.hexdigest()


def derive_fingerprint(public_b64: str) -> str:
    """Fingerprint = sha256(chave publica crua)[:16] — IDENTICA a custody.fingerprint().

    Levanta binascii.Error/ValueError se public_b64 nao for base64 valido.
    """
    return hashlib.sha256(base64.b64decode(public_b64, validate=True)).hexdigest()[:16]


def is_safe_name(name) -> bool:
    """True se `name` for um nome de arquivo SIMPLES (sem separador, `..`, drive ou caminho absoluto)."""
    return bool(
        isinstance(name, str) and name
        and name not in (".", "..")
        and not any(c in name for c in ("/", "\\", ":"))
        and not os.path.isabs(name)
    )


def canonical_payload(payload: dict) -> str:
    """Serializacao deterministica do bloco assinavel (ASCII, chaves ordenadas, sem espaco)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# --------------------------------------------------------------------------- #
# Geracao do manifesto
# --------------------------------------------------------------------------- #
def build_payload(*, product: str, version: str, date: str,
                  public_key_b64: str, fingerprint: str,
                  artifacts: list[dict]) -> dict:
    """Monta o bloco que sera assinado (a fonte da verdade). `artifacts` = [{name,sha256,size}]."""
    return {
        "product": product,
        "version": version,
        "date": date,
        "public_key": public_key_b64,
        "fingerprint": fingerprint,
        "artifacts": sorted(artifacts, key=lambda a: a["name"]),
    }


def scan_artifacts(dist_dir: str, names: list[str]) -> list[dict]:
    """Calcula sha256+tamanho de cada `name` em `dist_dir`. Erra se algum faltar."""
    out: list[dict] = []
    for name in names:
        p = os.path.join(dist_dir, name)
        if not os.path.isfile(p):
            raise FileNotFoundError(f"artefato nao encontrado: {p}")
        out.append({"name": name, "sha256": sha256_file(p), "size": os.path.getsize(p)})
    return out


def build_manifest(*, product: str, version: str, date: str,
                   public_key_b64: str, fingerprint: str,
                   artifacts: list[dict], sign_fn: Callable[[str], str]) -> dict:
    """Monta o RELEASE.json completo. `sign_fn` recebe a string e devolve a assinatura b64."""
    payload = build_payload(product=product, version=version, date=date,
                            public_key_b64=public_key_b64, fingerprint=fingerprint,
                            artifacts=artifacts)
    signed = canonical_payload(payload)
    return {
        "_about": ("Manifesto de release do Redoubt. INTEGRIDADE: 'signature' assina "
                   "'signed_payload'. AUTENTICIDADE: confira que o fingerprint impresso "
                   "bate com o publicado no repositorio oficial. Use verify_release.py."),
        "format": FORMAT,
        "algorithm": "ed25519",
        "signed_payload": signed,
        "signature": sign_fn(signed),
    }


def sha256sums_text(artifacts: list[dict]) -> str:
    """Conteudo do SHA256SUMS no formato padrao `<hex>  <name>` (compativel com sha256sum -c)."""
    return "".join(f"{a['sha256']}  {a['name']}\n"
                   for a in sorted(artifacts, key=lambda a: a["name"]))


# --------------------------------------------------------------------------- #
# Verificacao (CLI/teste). O verify_release.py standalone espelha esta logica.
# --------------------------------------------------------------------------- #
def _verify_sig(signed_payload: str, signature_b64: str, public_b64: str) -> bool:
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_b64, validate=True))
        pub.verify(sig, signed_payload.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def verify_manifest(manifest: dict, files_dir: str,
                    expect_fingerprint: str | None = None,
                    expect_pubkey: str | None = None) -> dict:
    """Verifica um RELEASE.json contra os arquivos em `files_dir`.

    Campos do retorno:
      signature_ok          assinatura valida sob a chave publica do payload
      fingerprint           DERIVADO da chave (confiavel), nunca o campo declarado
      fingerprint_declared_ok  campo 'fingerprint' do payload == derivado
      authentic             fingerprint derivado == expect_fingerprint (None = nao verificado)
      artifacts             [{name, expected, actual, present, ok, ...}]
      integrity_ok          assinatura + todos os hashes + fingerprint declarado coerente
      ok                    integrity_ok E authentic is True  (so "autentico" com ancora)
      error                 preenchido se o manifesto for malformado (nunca levanta)
    """
    result: dict = {"signature_ok": False, "fingerprint": None,
                    "fingerprint_declared_ok": None, "authentic": None,
                    "artifacts": [], "integrity_ok": False, "ok": False, "error": None}
    try:
        signed = manifest["signed_payload"]
        signature = manifest["signature"]
        if not isinstance(signed, str) or not isinstance(signature, str):
            raise ValueError("signed_payload/signature ausente ou nao-string")
        payload = json.loads(signed)
        if not isinstance(payload, dict):
            raise ValueError("signed_payload nao e um objeto JSON")
        pub = payload["public_key"]
        if not isinstance(pub, str):
            raise ValueError("public_key invalida")
        fp_derived = derive_fingerprint(pub)          # valida o base64 da chave tambem
        artifacts = payload.get("artifacts", [])
        if not isinstance(artifacts, list):
            raise ValueError("artifacts deve ser uma lista")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, binascii.Error) as e:
        result["error"] = f"manifesto malformado: {e}"
        return result

    result["signature_ok"] = _verify_sig(signed, signature, pub)
    result["fingerprint"] = fp_derived
    result["fingerprint_declared_ok"] = (payload.get("fingerprint") == fp_derived)
    # Autenticidade: expect_pubkey (32 bytes, FORTE) tem prioridade sobre o fingerprint
    # truncado de 64 bits. Liga a assinatura a chave inteira, imune a colisao de fp.
    if expect_pubkey is not None:
        result["authentic"] = _verify_sig(signed, signature, expect_pubkey)
    elif expect_fingerprint is not None:
        result["authentic"] = (fp_derived == expect_fingerprint)

    all_hashes_ok = True
    for a in artifacts:
        if not isinstance(a, dict):
            result["artifacts"].append({"name": None, "expected": None, "actual": None,
                                        "present": False, "ok": False, "invalid": repr(a)[:50]})
            all_hashes_ok = False
            continue
        name = a.get("name")
        expected = a.get("sha256")
        if not is_safe_name(name):
            result["artifacts"].append({"name": name, "expected": expected, "actual": None,
                                        "present": False, "ok": False, "unsafe": True})
            all_hashes_ok = False
            continue
        path = os.path.join(files_dir, name)
        present = os.path.isfile(path)
        actual = sha256_file(path) if present else None
        ok = present and actual == expected
        all_hashes_ok = all_hashes_ok and ok
        result["artifacts"].append({"name": name, "expected": expected, "actual": actual,
                                    "present": present, "ok": ok})

    result["integrity_ok"] = bool(result["signature_ok"] and all_hashes_ok
                                  and artifacts and result["fingerprint_declared_ok"])
    result["ok"] = bool(result["integrity_ok"] and result["authentic"] is True)
    return result


# --------------------------------------------------------------------------- #
# CLI:  python -m notepy.release make|verify
# --------------------------------------------------------------------------- #
def _default_artifacts(dist_dir: str, version: str) -> list[str]:
    cands = [f"Redoubt-Setup-{version}.exe", "Redoubt.exe"]
    return [n for n in cands if os.path.isfile(os.path.join(dist_dir, n))]


def _cmd_make(args) -> int:
    from datetime import date as _date
    from notepy import APP_NAME, APP_VERSION, custody

    version = args.version or APP_VERSION
    when = args.date or _date.today().isoformat()
    names = args.artifacts or _default_artifacts(args.dist, version)
    if not names:
        print(f"[ERRO] nenhum artefato em {args.dist!r} "
              f"(esperava Redoubt-Setup-{version}.exe e/ou Redoubt.exe).")
        return 1

    artifacts = scan_artifacts(args.dist, names)
    manifest = build_manifest(
        product=APP_NAME, version=version, date=when,
        public_key_b64=custody.public_key_b64(), fingerprint=custody.fingerprint(),
        artifacts=artifacts, sign_fn=custody.sign)

    man_path = os.path.join(args.dist, MANIFEST_NAME)
    sums_path = os.path.join(args.dist, SUMS_NAME)
    with open(man_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=True, indent=2)
        fh.write("\n")
    with open(sums_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(sha256sums_text(artifacts))

    print(f"Assinado pela chave de fingerprint: {custody.fingerprint()}")
    for a in artifacts:
        print(f"  {a['sha256']}  {a['name']}  ({a['size']:,} bytes)")
    print(f"\nGerado:\n  {man_path}\n  {sums_path}")
    print("PUBLIQUE este fingerprint no repositorio para terceiros autenticarem a chave.")
    return 0


def _cmd_verify(args) -> int:
    man_path = args.manifest or os.path.join(args.dir, MANIFEST_NAME)
    try:
        with open(man_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERRO] nao consegui ler o manifesto {man_path!r}: {e}")
        return 2

    r = verify_manifest(manifest, args.dir, expect_fingerprint=args.expect_fingerprint,
                        expect_pubkey=args.expect_pubkey)
    if r["error"]:
        print(f"[ERRO] {r['error']}")
        return 2

    print(f"Assinatura Ed25519: {'OK' if r['signature_ok'] else 'INVALIDA'}")
    print(f"Fingerprint da chave (derivado): {r['fingerprint']}")
    if not r["fingerprint_declared_ok"]:
        print("  [ALERTA] o campo 'fingerprint' do manifesto NAO corresponde a chave!")
    if r["authentic"] is None:
        print("  autenticidade: NAO verificada (passe --expect-fingerprint <fp publicado>)")
    else:
        print(f"  autenticidade: {'chave CONFERE' if r['authentic'] else 'chave NAO confere'}")
    print("Artefatos:")
    for a in r["artifacts"]:
        if a.get("unsafe"):
            tag = "NOME INSEGURO"
        elif a.get("invalid") is not None:
            tag = "ENTRADA INVALIDA"
        elif not a["present"]:
            tag = "AUSENTE"
        elif a["ok"]:
            tag = "OK"
        else:
            tag = "HASH NAO CONFERE"
        print(f"  [{tag}] {a['name']}")
    print(f"\nIntegridade: {'OK' if r['integrity_ok'] else 'FALHOU'}")
    print(f"Veredito: {'INTEGRO E AUTENTICO' if r['ok'] else 'NAO CONFIRMADO'}")
    return 0 if r["ok"] else 1


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="python -m notepy.release",
        description="Gera/verifica o manifesto de release assinado do Redoubt.")
    sub = p.add_subparsers(dest="cmd", required=True)

    mk = sub.add_parser("make", help="gera RELEASE.json + SHA256SUMS em dist/")
    mk.add_argument("--dist", default="dist", help="diretorio dos binarios (default: dist)")
    mk.add_argument("--version", default=None, help="default: APP_VERSION")
    mk.add_argument("--date", default=None, help="YYYY-MM-DD (default: hoje)")
    mk.add_argument("--artifacts", nargs="*", default=None,
                    help="nomes de arquivo (default: auto-detecta em dist/)")

    vf = sub.add_parser("verify", help="verifica os binarios de um diretorio")
    vf.add_argument("dir", help="diretorio com os binarios + RELEASE.json")
    vf.add_argument("--manifest", default=None,
                    help="caminho do RELEASE.json (default: <dir>/RELEASE.json)")
    vf.add_argument("--expect-fingerprint", default=None,
                    help="fingerprint publicado (16 hex); confirma AUTENTICIDADE")
    vf.add_argument("--expect-pubkey", default=None,
                    help="chave publica esperada (b64, 32 bytes); autenticacao FORTE, tem prioridade")

    args = p.parse_args(argv)
    return _cmd_make(args) if args.cmd == "make" else _cmd_verify(args)


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
