#!/usr/bin/env python3
"""Verificador standalone de SELO do Redoubt — rode SEM instalar o Redoubt.

Um selo (`<arquivo>.rdbt-seal`) prova a ORIGEM e a INTEGRIDADE de um arquivo:
  1) AUTENTICIDADE: a assinatura Ed25519 do selo bate com a CHAVE PUBLICA DO AUTOR
     embutida abaixo (`AUTHOR_PUBKEY_B64`). Como este arquivo vem do repositorio oficial,
     a chave de confianca chega pelo mesmo canal — forjar exigiria a chave PRIVADA do autor.
  2) INTEGRIDADE: o SHA-256 do arquivo bate com o valor que foi assinado no selo. O selo
     fixa o CONTEUDO: so confere com o conteudo exato que foi selado.

Uso:
    python verify_seal.py ARQUIVO                      # le ARQUIVO.rdbt-seal ao lado
    python verify_seal.py ARQUIVO --seal CAMINHO       # selo em outro caminho
    python verify_seal.py ARQUIVO --pubkey <b64>       # selo de OUTRO autor (chave por canal confiavel)

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

# Chaves ANTERIORES do autor, APOSENTADAS. A 4e391f28930f3b6e se perdeu junto com a maquina que a
# guardava (disco destruido: a chave nao vazou, so deixou de existir). Como nao sela mais nada, so
# vale para selos com `sealed_at` ate a data da aposentadoria.
RETIRED_AUTHOR_KEYS = (
    {"pubkey": "RZZBbCP6irycPMcBLFs5raHw5gONJOU5LMYZwGawrBA=", "fingerprint": "4e391f28930f3b6e",
     "retired": "2026-09-24"},
)
# =============================================================================

SEAL_SUFFIX = ".rdbt-seal"
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


def _sealed_date(payload):
    """'2026-06-15T00:00:00+00:00' -> '2026-06-15'. None se o campo nao tiver esse formato."""
    v = payload.get("sealed_at")
    if not isinstance(v, str) or len(v) < 10:
        return None
    d = v[:10]
    if not (d[4] == d[7] == "-" and (d[:4] + d[5:7] + d[8:10]).isdigit()):
        return None
    return d


def _trust_chain(trust_pubkey):
    """Chaves aceitas, em ordem: [(pubkey, metadados_se_aposentada)]. Com `--pubkey` explicito,
    SO ela (quem escolheu a ancora decide); sem, a chave atual do autor + as aposentadas."""
    if trust_pubkey is not None:
        return [(trust_pubkey, None)]
    return [(AUTHOR_PUBKEY_B64, None)] + [(k["pubkey"], k) for k in RETIRED_AUTHOR_KEYS]


def verify_file(file_path, seal_path=None, trust_pubkey=None):
    """Verifica `file_path` contra seu selo, ancorado na chave de confianca.

    `trust_pubkey=None` (padrao) usa a chave do AUTOR embutida acima e aceita as chaves
    aposentadas so para selos anteriores a aposentadoria. Um `trust_pubkey` explicito vira a
    unica ancora.

    Retorna (ok: bool, linhas: list[str]). `ok` exige AUTENTICIDADE (assinatura valida sob a
    chave de confianca) E INTEGRIDADE (arquivo presente e sha256 batendo com o selado).
    Nunca levanta por entrada malformada. O `name` do selo e so informativo: a amarra e o hash.
    """
    sp = seal_path or (file_path + SEAL_SUFFIX)
    try:
        with open(sp, encoding="utf-8") as fh:
            seal = json.load(fh)
        signed = seal["signed_payload"]
        signature = seal["signature"]
        if not isinstance(signed, str) or not isinstance(signature, str):
            raise ValueError("signed_payload/signature ausente ou nao-string")
        payload = json.loads(signed)
        if not isinstance(payload, dict):
            raise ValueError("signed_payload nao e um objeto JSON")
        expected_sha = payload.get("sha256")
        if not isinstance(expected_sha, str):
            raise ValueError("sha256 ausente no selo")
        chain = _trust_chain(trust_pubkey)
        trust_fp = fingerprint_of(chain[0][0])   # valida a ancora
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, binascii.Error) as e:
        return False, [f"[ERRO] selo/ancora invalido ({sp}): {e}"]

    # 1) AUTENTICIDADE: a assinatura confere com uma CHAVE DE CONFIANCA (nunca a do payload).
    # Chave aposentada so vale para selos feitos ate a data da aposentadoria.
    authentic, retired, out_of_range = False, None, None
    sealed = _sealed_date(payload)
    for pub, meta in chain:
        if not verify_signature(signed, signature, pub):
            continue
        if meta is not None and (sealed is None or sealed > meta["retired"]):
            out_of_range = meta
            continue
        authentic, retired = True, meta
        trust_fp = fingerprint_of(pub)
        break
    out = [f"Chave de confianca (fingerprint): {trust_fp}"]
    if retired is not None:
        out.append(f"  (chave ANTERIOR do autor, aposentada em {retired['retired']}: vale para "
                   f"selos feitos ate essa data)")
    out.append(f"Assinatura confere com a chave do autor: {'SIM' if authentic else 'NAO'}")
    if out_of_range is not None:
        out.append(f"  (assinado pela chave APOSENTADA {out_of_range['fingerprint']}, que so vale para "
                   f"selos ate {out_of_range['retired']}; este selo declara {payload.get('sealed_at')!r})")
    elif not authentic:
        declared = payload.get("public_key")
        if isinstance(declared, str):
            try:
                out.append(f"  (o selo foi assinado por OUTRA chave, fingerprint {fingerprint_of(declared)})")
            except (ValueError, binascii.Error):
                out.append("  (o selo declara uma chave publica invalida)")

    # 2) INTEGRIDADE: o arquivo existe e seu sha256 bate com o selado
    declared_name = payload.get("name")
    out.append(f"Arquivo: {os.path.basename(file_path)}")
    if not os.path.isfile(file_path):
        out.append("  [AUSENTE] arquivo-alvo nao encontrado")
        content_ok = False
    else:
        # A leitura pode falhar mesmo existindo (travado por OneDrive/AV, sem permissao,
        # ou removido na janela TOCTOU apos o isfile). Tratamos como falha, nunca crash.
        try:
            content_ok = (sha256_file(file_path) == expected_sha)
            out.append(f"  [{'OK' if content_ok else 'HASH NAO CONFERE'}] "
                       f"{'conteudo confere com o selo' if content_ok else 'o conteudo mudou desde que foi selado'}")
        except OSError as e:
            content_ok = False
            out.append(f"  [ERRO] nao consegui ler o arquivo-alvo: {e}")
    if isinstance(declared_name, str) and declared_name != os.path.basename(file_path):
        out.append(f"  (nota: selado originalmente como {declared_name!r})")
    trail = payload.get("trail")
    if isinstance(trail, dict):
        out.append(f"  trilha selada: seq={trail.get('seq')} head={str(trail.get('head_hash'))[:16]}...")

    ok = bool(authentic and content_ok)
    out += ["", f"Veredito: {'INTEGRO E AUTENTICO' if ok else 'FALHOU'}"]
    if ok:
        out.append(f"(Confirme que {trust_fp} e o fingerprint publicado no repositorio oficial.)")
    return ok, out


def main(argv=None):
    p = argparse.ArgumentParser(description="Verifica o selo de proveniencia de um arquivo (standalone).")
    p.add_argument("file", help="arquivo a verificar")
    p.add_argument("--seal", default=None,
                   help="caminho do selo (default: <arquivo>.rdbt-seal)")
    p.add_argument("--pubkey", default=None,
                   help="chave publica de confianca em base64 (default: a do autor oficial, "
                        "mais as chaves aposentadas para os selos anteriores a aposentadoria)")
    args = p.parse_args(argv)
    ok, lines = verify_file(args.file, args.seal, trust_pubkey=args.pubkey)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
