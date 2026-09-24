#!/usr/bin/env python3
"""Backup / restauracao da identidade do Redoubt (CLI).

A identidade Ed25519 desta instalacao e a ancora de confianca do projeto: ela assina o
`RELEASE.json` de cada release, os selos `.rdbt-seal` e as ancoras da trilha. Os verificadores
standalone tem a chave PUBLICA do autor EMBUTIDA — perde-la significa nunca mais poder assinar
como aquele fingerprint, e um release novo com chave nova e indistinguivel de falsificacao.

Uso:
    python tools/backup_identity.py make [-o ARQUIVO] [--keyfile K] [--force]
    python tools/backup_identity.py check ARQUIVO [--keyfile K]
    python tools/backup_identity.py restore ARQUIVO [--dir D] [--keyfile K] [--force]

O pacote e um Cofre `.rdbt` (AES-256-GCM + Argon2id) com extensao `.rdbtbak`. A senha e pedida
sem eco; o material de chave NUNCA e impresso. `make` sempre REABRE o pacote e confere o
fingerprint antes de dizer que o backup existe.

Guia completo (incluindo rotacao assinada): docs/CUSTODY.md
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from notepy import custody, idbackup     # precisa do sys.path.insert acima


def _pedir_senha(confirmar: bool, rotulo: str) -> str:
    pw = getpass.getpass(f"{rotulo}: ")
    if confirmar:
        if pw != getpass.getpass("Confirme a senha: "):
            raise SystemExit("[ERRO] as senhas nao conferem.")
    return pw


def _ler_keyfile(caminho: str | None) -> bytes | None:
    if not caminho:
        return None
    try:
        with open(caminho, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise SystemExit(f"[ERRO] nao consegui ler o arquivo-chave: {exc}") from exc


def cmd_make(args) -> int:
    keyfile = _ler_keyfile(args.keyfile)
    if not idbackup.local_identity_exists():
        print("[ERRO] nenhuma identidade local encontrada — nada a copiar.")
        print(f"       diretorio de dados: {custody._data_dir()}")
        return 1
    atual = None
    if custody.is_protected():
        print("A identidade local esta PROTEGIDA — informe a credencial dela para ler a chave.")
        atual = _pedir_senha(False, "Senha da identidade")
    x_senha = None
    if custody.recipient_exists() and not custody.recipient_unlocked():
        print("A chave de destinatario (X25519) esta PROTEGIDA — informe a credencial dela para "
              "inclui-la no backup.")
        x_senha = _pedir_senha(False, "Senha da chave de destinatario")
    try:
        payload = idbackup.collect_local(atual, keyfile=keyfile if custody.is_protected() else None,
                                         recipient_passphrase=x_senha or None)
    except idbackup.BackupError as exc:
        print(f"[ERRO] {exc}")
        return 1
    if not payload.get("x25519_private") and custody.recipient_exists():
        print("[AVISO] a chave X25519 de destinatario esta ILEGIVEL e nao entrou no pacote. "
              "Perde-la significa perder o acesso aos cofres selados para voce.")

    print("\nAgora crie a credencial DO BACKUP (pode ser diferente da senha da identidade).")
    print("Ela e zero-knowledge: esquecer = perder o backup. Guarde-a fora desta maquina.")
    pw = _pedir_senha(True, "Senha do backup")
    if not pw and not keyfile:
        print("[ERRO] backup sem credencial nao seria cifrado — abortado.")
        return 1

    destino = args.out or os.path.join(
        os.getcwd(),
        f"redoubt-identity-{payload['ed25519_fingerprint']}-"
        f"{payload['created_at'][:10].replace('-', '')}.rdbtbak")
    if os.path.exists(destino) and not args.force:
        print(f"[ERRO] {destino} ja existe (use --force para sobrescrever).")
        return 1
    try:
        blob = idbackup.make_blob(payload, password=pw or None, keyfile=keyfile)
        # PROVA antes de prometer: reabre o pacote e confere o fingerprint derivado da chave.
        idbackup.verify_blob(blob, password=pw or None, keyfile=keyfile,
                             expected_ed_fingerprint=payload["ed25519_fingerprint"])
        custody._atomic_write(destino, blob)
    except idbackup.BackupError as exc:
        print(f"[ERRO] {exc}")
        return 1
    except OSError as exc:
        print(f"[ERRO] nao consegui gravar o backup: {exc}")
        return 1

    print(f"\nBackup criado e VERIFICADO: {destino}")
    print(idbackup.summary(payload))
    print("\nGuarde DUAS copias, offline e em lugares diferentes (ex.: pendrive + outra maquina).")
    print("Confira a restauracao num diretorio de teste:")
    print(f"  python tools/backup_identity.py restore \"{destino}\" --dir ./teste-restore")
    return 0


def cmd_check(args) -> int:
    try:
        with open(args.arquivo, "rb") as fh:
            blob = fh.read()
    except OSError as exc:
        print(f"[ERRO] nao consegui ler {args.arquivo}: {exc}")
        return 1
    keyfile = _ler_keyfile(args.keyfile)
    pw = _pedir_senha(False, "Senha do backup")
    try:
        payload = idbackup.verify_blob(blob, password=pw or None, keyfile=keyfile)
    except idbackup.BackupError as exc:
        print(f"[ERRO] {exc}")
        return 1
    print("\nPacote VALIDO (abre e o fingerprint confere com a chave que ele carrega).")
    print(idbackup.summary(payload))
    local = custody.fingerprint() if idbackup.local_identity_exists() else None
    if local:
        igual = local == payload.get("ed25519_fingerprint")
        print(f"identidade local: {local}  ->  {'MESMA do backup' if igual else 'DIFERENTE do backup'}")
    else:
        print("identidade local: (nenhuma nesta instalacao)")
    return 0


def cmd_restore(args) -> int:
    try:
        with open(args.arquivo, "rb") as fh:
            blob = fh.read()
    except OSError as exc:
        print(f"[ERRO] nao consegui ler {args.arquivo}: {exc}")
        return 1
    keyfile = _ler_keyfile(args.keyfile)
    pw = _pedir_senha(False, "Senha do backup")
    destino = args.dir or custody._data_dir()
    try:
        payload = idbackup.verify_blob(blob, password=pw or None, keyfile=keyfile)
        escritos = idbackup.restore(payload, destino, force=args.force)
    except idbackup.BackupError as exc:
        print(f"[ERRO] {exc}")
        return 1
    print(f"\nRestaurado em {destino}:")
    for nome in escritos:
        print(f"  - {nome}")
    print(idbackup.summary(payload))
    print("\nA identidade voltou na forma LEGADA (chave em claro no disco). Proteja-a de novo no "
          "app: Seguranca > Proteger identidade com senha.")
    if payload.get("x25519_private"):
        print("A chave de destinatario (X25519) tambem voltou em claro: Seguranca > Proteger chave "
              "de destinatario com senha.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Backup/restauracao da identidade do Redoubt (Ed25519 + X25519).")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("make", help="cria um pacote de backup cifrado da identidade local")
    m.add_argument("-o", "--out", help="caminho do pacote (default: ./redoubt-identity-<fp>-<data>.rdbtbak)")
    m.add_argument("--keyfile", help="arquivo-chave adicional (2o fator do backup)")
    m.add_argument("--force", action="store_true", help="sobrescrever o pacote se ja existir")
    m.set_defaults(func=cmd_make)

    c = sub.add_parser("check", help="abre um pacote e mostra o que ha nele (sem restaurar)")
    c.add_argument("arquivo")
    c.add_argument("--keyfile", help="arquivo-chave do backup")
    c.set_defaults(func=cmd_check)

    r = sub.add_parser("restore", help="grava as chaves do pacote no diretorio de dados")
    r.add_argument("arquivo")
    r.add_argument("--dir", help="diretorio de destino (default: o do app)")
    r.add_argument("--keyfile", help="arquivo-chave do backup")
    r.add_argument("--force", action="store_true",
                   help="SUBSTITUIR uma identidade existente (compare os fingerprints antes)")
    r.set_defaults(func=cmd_restore)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
