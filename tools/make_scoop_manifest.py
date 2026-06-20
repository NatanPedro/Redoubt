#!/usr/bin/env python3
"""Gera/atualiza scoop/redoubt.json a partir do APP_VERSION e do sha256 de dist/Redoubt.exe.

Chamado pelo build-installer.bat apos gerar os binarios: mantem o manifesto Scoop SEMPRE em
sincronia com o release (versao fixa = fonte da verdade em notepy/__init__.py; hash = o binario
recem-buildado). Sem dependencias alem da stdlib + notepy. Tudo local.
"""

import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BASE = "https://github.com/NatanPedro/Redoubt/releases/download"


def main() -> int:
    sys.path.insert(0, ROOT)
    from notepy import APP_VERSION

    exe = os.path.join(ROOT, "dist", "Redoubt.exe")
    if not os.path.isfile(exe):
        print("[ERRO] dist/Redoubt.exe nao existe — rode build.bat primeiro.")
        return 1

    h = hashlib.sha256()
    with open(exe, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()

    manifest = {
        "version": APP_VERSION,
        "description": ("Editor onde a seguranca e a identidade: vigia segredos, sela arquivos "
                        "como evidencia e mantem cadeia de custodia. Nada vaza sem voce mandar."),
        "homepage": "https://github.com/NatanPedro/Redoubt",
        "license": "MIT",
        "architecture": {"64bit": {
            "url": f"{_BASE}/v{APP_VERSION}/Redoubt.exe",
            "hash": digest,
        }},
        "bin": "Redoubt.exe",
        "shortcuts": [["Redoubt.exe", "Redoubt"]],
        "checkver": "github",
        "autoupdate": {"architecture": {"64bit": {
            "url": f"{_BASE}/v$version/Redoubt.exe",
            "hash": {"url": f"{_BASE}/v$version/SHA256SUMS"},
        }}},
        "notes": [
            "Redoubt instalado. O Scoop ja conferiu o SHA-256 do binario.",
            "Para verificar tambem a ASSINATURA (opcional, recomendado): baixe verify_release.py,",
            "RELEASE.json e SHA256SUMS do release e rode  python verify_release.py  na mesma pasta.",
            "Fingerprint oficial do autor: 4e391f28930f3b6e",
        ],
    }

    out = os.path.join(ROOT, "scoop", "redoubt.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=True, indent=4)
        fh.write("\n")
    print(f"scoop/redoubt.json atualizado: v{APP_VERSION}  sha256={digest[:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
