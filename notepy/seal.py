"""Selo de proveniencia assinado — cada arquivo vira evidencia portatil.

Um SELO (`<arquivo>.rdbt-seal`) e um artefato JSON auto-contido que liga o CONTEUDO de um
arquivo a uma identidade Ed25519: nome + sha256 + tamanho + timestamp + (opcional) o head da
trilha de custodia no momento do selo, tudo assinado. Diferente da assinatura crua (`.sig`), o
selo VIAJA com o arquivo e prova, offline e sem a sua maquina, a ORIGEM e a INTEGRIDADE do
conteudo. Verifique com `verify_seal.py` (standalone, sem instalar o Redoubt) ou com
`python -m notepy.seal verify <arquivo>`.

Formato `RDBT-SEAL1`: o que importa e o **`signed_payload`** — uma STRING JSON canonica com
nome, sha256, tamanho, data, chave publica, fingerprint e o head da trilha. A `signature`
(Ed25519) cobre exatamente essa string; o verificador checa a assinatura SOBRE A STRING e so
entao a parseia (zero divergencia de reserializacao entre gerador e verificador).

Modelo de confianca (a mesma licao do release, pos red-team):
- INTEGRIDADE = a assinatura e valida E o sha256 do arquivo bate com o valor assinado. O selo
  fixa o CONTEUDO: um selo so confere com o conteudo exato que foi selado (anti-substituicao).
- AUTENTICIDADE = a chave que assinou e MESMO a do autor. A chave publica viaja no payload
  (auto-assinado), entao a assinatura sozinha NAO prova autoria — um atacante re-assina com a
  propria chave. Por isso o fingerprint e sempre DERIVADO da chave (`sha256(pub)[:16]`), nunca
  lido do campo livre, e `ok` so e True quando a chave bate com uma ancora de confianca
  (`expect_pubkey`/`expect_fingerprint`, ou a embutida no `verify_seal.py`).
- O `name` viaja assinado (logo, a prova de adulteracao), mas e INFORMATIVO: a amarra forte e o
  hash do conteudo, nao o nome — renomear o arquivo nao muda o conteudo selado.
- O HEAD DA TRILHA (`seq`/`head_hash`) e uma ASSERCAO assinada do autor: so quem tem a audit.log
  dele cruza com a trilha real. Para terceiros e proveniencia forense, nao verificavel sozinho.

Nucleo puro: sem Qt, sem rede; a assinatura e injetada (`sign_fn`).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Primitivas puras reusadas do release (mesma formula de fingerprint/hash/serializacao):
from notepy.release import (canonical_payload, derive_fingerprint, is_safe_name,
                            sha256_file)

FORMAT = "RDBT-SEAL1"
SEAL_SUFFIX = ".rdbt-seal"


# --------------------------------------------------------------------------- #
# Geracao do selo
# --------------------------------------------------------------------------- #
def build_payload(*, name: str, sha256: str, size: int, sealed_at: str,
                  public_key_b64: str, fingerprint: str,
                  trail: dict | None) -> dict:
    """Monta o bloco que sera assinado (a fonte da verdade do selo)."""
    return {
        "format": FORMAT,
        "name": name,
        "sha256": sha256,
        "size": size,
        "sealed_at": sealed_at,
        "public_key": public_key_b64,
        "fingerprint": fingerprint,
        "trail": trail,                  # {"seq": int, "head_hash": str} ou None
    }


def build_seal(*, name: str, sha256: str, size: int, sealed_at: str,
               public_key_b64: str, fingerprint: str, trail: dict | None,
               sign_fn: Callable[[str], str]) -> dict:
    """Monta o `.rdbt-seal` completo. `sign_fn` recebe a string canonica e devolve a assinatura b64."""
    payload = build_payload(name=name, sha256=sha256, size=size, sealed_at=sealed_at,
                            public_key_b64=public_key_b64, fingerprint=fingerprint,
                            trail=trail)
    signed = canonical_payload(payload)
    return {
        "_about": ("Selo de proveniencia do Redoubt. INTEGRIDADE: 'signature' assina "
                   "'signed_payload', que fixa o sha256 do conteudo. AUTENTICIDADE: confira "
                   "que o fingerprint impresso bate com o publicado pelo autor. "
                   "Verifique com verify_seal.py."),
        "format": FORMAT,
        "algorithm": "ed25519",
        "signed_payload": signed,
        "signature": sign_fn(signed),
    }


def seal_file(path: str, *, sign_fn: Callable[[str], str], public_key_b64: str,
              fingerprint: str, sealed_at: str, trail: dict | None = None) -> dict:
    """Sela o arquivo em `path`: calcula nome/sha256/tamanho e assina. Le o arquivo em blocos."""
    return build_seal(
        name=os.path.basename(path),
        sha256=sha256_file(path),
        size=os.path.getsize(path),
        sealed_at=sealed_at,
        public_key_b64=public_key_b64,
        fingerprint=fingerprint,
        trail=trail,
        sign_fn=sign_fn,
    )


def current_trail() -> dict | None:
    """Snapshot READ-ONLY do head da trilha de custodia: {seq, head_hash}, ou None se vazia/invalida.

    Nao cria identidade nem escreve nada (so le a audit.log). E uma assercao assinada junto ao selo.
    """
    from notepy import custody
    entries = custody.read_audit()
    if not entries:
        return None
    head = entries[-1]
    hh = head.get("hash", "")
    if not (isinstance(hh, str) and len(hh) == 64):
        return None
    return {"seq": head.get("seq", len(entries)), "head_hash": hh}


# --------------------------------------------------------------------------- #
# Verificacao (CLI/teste). O verify_seal.py standalone espelha esta logica.
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


def verify_seal(seal: dict, file_path: str,
                expect_fingerprint: str | None = None,
                expect_pubkey: str | None = None) -> dict:
    """Verifica um selo contra o arquivo em `file_path`.

    Campos do retorno:
      signature_ok            assinatura valida sob a chave publica do payload
      fingerprint             DERIVADO da chave (confiavel), nunca o campo declarado
      fingerprint_declared_ok campo 'fingerprint' do payload == derivado
      authentic               fingerprint/chave == esperado (None = nao verificado)
      declared_name           nome assinado no selo (informativo)
      name                    basename do arquivo-alvo
      name_match              basename(alvo) == declared_name  (informativo, nao afeta 'ok')
      present                 o arquivo-alvo existe
      sha256 / expected_sha   hash do alvo / hash assinado
      size_ok                 tamanho do alvo == tamanho assinado
      content_ok              present e sha256 == assinado (a amarra forte)
      trail                   {seq, head_hash} assinado (informativo/forense)
      integrity_ok            assinatura + conteudo + fingerprint declarado coerente
      ok                      integrity_ok E authentic is True
      error                   preenchido se o selo for malformado (nunca levanta)

    NOTA: o `declared_name` do selo NUNCA e usado para abrir/montar caminho — so o `file_path`
    fornecido pelo verificador e lido. Logo nao ha superficie de path traversal aqui.
    """
    result: dict = {"signature_ok": False, "fingerprint": None,
                    "fingerprint_declared_ok": None, "authentic": None,
                    "declared_name": None, "name": os.path.basename(file_path),
                    "name_match": None, "present": False, "sha256": None,
                    "expected_sha": None, "size_ok": False, "content_ok": False,
                    "trail": None, "io_error": None,
                    "integrity_ok": False, "ok": False, "error": None}
    try:
        signed = seal["signed_payload"]
        signature = seal["signature"]
        if not isinstance(signed, str) or not isinstance(signature, str):
            raise ValueError("signed_payload/signature ausente ou nao-string")
        payload = json.loads(signed)
        if not isinstance(payload, dict):
            raise ValueError("signed_payload nao e um objeto JSON")
        pub = payload["public_key"]
        if not isinstance(pub, str):
            raise ValueError("public_key invalida")
        fp_derived = derive_fingerprint(pub)          # valida o base64 da chave tambem
        expected_sha = payload.get("sha256")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, binascii.Error) as e:
        result["error"] = f"selo malformado: {e}"
        return result

    result["signature_ok"] = _verify_sig(signed, signature, pub)
    result["fingerprint"] = fp_derived
    result["fingerprint_declared_ok"] = (payload.get("fingerprint") == fp_derived)
    # Autenticidade: expect_pubkey (32 bytes, FORTE) tem prioridade sobre o fingerprint truncado.
    if expect_pubkey is not None:
        result["authentic"] = _verify_sig(signed, signature, expect_pubkey)
    elif expect_fingerprint is not None:
        result["authentic"] = (fp_derived == expect_fingerprint)

    result["declared_name"] = payload.get("name")
    trail = payload.get("trail")
    result["trail"] = trail if isinstance(trail, dict) else None   # so dict|None p/ consumidores
    result["expected_sha"] = expected_sha
    result["name_match"] = (result["declared_name"] == result["name"])

    present = os.path.isfile(file_path)
    result["present"] = present
    if present:
        # A leitura do alvo pode falhar mesmo existindo: travado por OneDrive/AV, sem permissao,
        # ou removido na janela TOCTOU apos o isfile. Tratamos como nao-verificavel, sem levantar.
        try:
            result["sha256"] = sha256_file(file_path)
            result["size_ok"] = (payload.get("size") == os.path.getsize(file_path))
        except OSError as e:
            result["io_error"] = str(e)
    result["content_ok"] = bool(present and not result["io_error"]
                                and isinstance(expected_sha, str)
                                and result["sha256"] == expected_sha)

    result["integrity_ok"] = bool(result["signature_ok"] and result["content_ok"]
                                  and result["fingerprint_declared_ok"])
    result["ok"] = bool(result["integrity_ok"] and result["authentic"] is True)
    return result


# --------------------------------------------------------------------------- #
# CLI:  python -m notepy.seal make|verify
# --------------------------------------------------------------------------- #
def _cmd_make(args) -> int:
    from datetime import datetime, timezone
    from notepy import custody

    if not os.path.isfile(args.file):
        print(f"[ERRO] arquivo nao encontrado: {args.file!r}")
        return 2
    if custody.is_protected():               # identidade com senha: destrava antes de assinar
        import getpass
        for _ in range(3):
            try:
                pw = getpass.getpass("Senha da identidade Redoubt (para selar): ")
            except (EOFError, KeyboardInterrupt):
                print("\n[ERRO] selagem cancelada.")
                return 1
            if custody.unlock_identity(pw):
                break
            print("Senha incorreta.")
        else:
            print("[ERRO] nao consegui destravar a identidade.")
            return 1

    when = args.date or datetime.now(timezone.utc).isoformat(timespec="seconds")
    out_path = args.out or (args.file + SEAL_SUFFIX)
    # Ler o arquivo-a-selar e gravar o .rdbt-seal podem falhar (lock OneDrive/AV, permissao,
    # TOCTOU): erro limpo, nunca traceback. Nao registra "selou" se nao chegou a gravar o selo.
    try:
        obj = seal_file(args.file, sign_fn=custody.sign,
                        public_key_b64=custody.public_key_b64(),
                        fingerprint=custody.fingerprint(),
                        sealed_at=when, trail=current_trail())
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=True, indent=2)
            fh.write("\n")
    except OSError as e:
        print(f"[ERRO] falha de IO ao selar {args.file!r}: {e}")
        return 2

    payload = json.loads(obj["signed_payload"])
    custody.log_event("selou", os.path.basename(args.file), payload["sha256"])
    print(f"Selado por: {custody.fingerprint()}")
    print(f"  arquivo : {payload['name']}  ({payload['size']:,} bytes)")
    print(f"  sha256  : {payload['sha256']}")
    if isinstance(payload.get("trail"), dict):
        print(f"  trilha  : seq={payload['trail']['seq']} head={payload['trail']['head_hash'][:16]}...")
    print(f"\nGerado: {out_path}")
    print("PUBLIQUE seu fingerprint para terceiros autenticarem o selo.")
    return 0


def _cmd_verify(args) -> int:
    seal_path = args.seal or (args.file + SEAL_SUFFIX)
    try:
        with open(seal_path, encoding="utf-8") as fh:
            seal = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERRO] nao consegui ler o selo {seal_path!r}: {e}")
        return 2

    r = verify_seal(seal, args.file, expect_fingerprint=args.expect_fingerprint,
                    expect_pubkey=args.expect_pubkey)
    if r["error"]:
        print(f"[ERRO] {r['error']}")
        return 2

    print(f"Assinatura Ed25519: {'OK' if r['signature_ok'] else 'INVALIDA'}")
    print(f"Fingerprint da chave (derivado): {r['fingerprint']}")
    if not r["fingerprint_declared_ok"]:
        print("  [ALERTA] o campo 'fingerprint' do selo NAO corresponde a chave!")
    if r["authentic"] is None:
        print("  autenticidade: NAO verificada (passe --expect-fingerprint <fp publicado>)")
    else:
        print(f"  autenticidade: {'chave CONFERE' if r['authentic'] else 'chave NAO confere'}")
    print(f"Arquivo: {r['name']}")
    if not r["present"]:
        print("  [AUSENTE] arquivo-alvo nao encontrado")
    elif r["io_error"]:
        print(f"  [ERRO] nao consegui ler o arquivo-alvo: {r['io_error']}")
    elif r["content_ok"]:
        print("  [OK] conteudo confere com o selo")
    else:
        print("  [HASH NAO CONFERE] o conteudo mudou desde que foi selado")
    if r["declared_name"] is not None and not r["name_match"]:
        print(f"  (nota: selado originalmente como {r['declared_name']!r})")
    if isinstance(r.get("trail"), dict):
        print(f"  trilha selada: seq={r['trail'].get('seq')} head={str(r['trail'].get('head_hash'))[:16]}...")
    print(f"\nIntegridade: {'OK' if r['integrity_ok'] else 'FALHOU'}")
    print(f"Veredito: {'INTEGRO E AUTENTICO' if r['ok'] else 'NAO CONFIRMADO'}")
    return 0 if r["ok"] else 1


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="python -m notepy.seal",
        description="Gera/verifica o selo de proveniencia assinado de um arquivo.")
    sub = p.add_subparsers(dest="cmd", required=True)

    mk = sub.add_parser("make", help="sela um arquivo -> <arquivo>.rdbt-seal")
    mk.add_argument("file", help="arquivo a selar")
    mk.add_argument("--out", default=None, help="caminho do selo (default: <arquivo>.rdbt-seal)")
    mk.add_argument("--date", default=None, help="timestamp ISO (default: agora, UTC)")

    vf = sub.add_parser("verify", help="verifica um arquivo contra seu selo")
    vf.add_argument("file", help="arquivo a verificar")
    vf.add_argument("--seal", default=None, help="caminho do selo (default: <arquivo>.rdbt-seal)")
    vf.add_argument("--expect-fingerprint", default=None,
                    help="fingerprint publicado (16 hex); confirma AUTENTICIDADE")
    vf.add_argument("--expect-pubkey", default=None,
                    help="chave publica esperada (b64, 32 bytes); autenticacao FORTE, tem prioridade")

    args = p.parse_args(argv)
    return _cmd_make(args) if args.cmd == "make" else _cmd_verify(args)


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
