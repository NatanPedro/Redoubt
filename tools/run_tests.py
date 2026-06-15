#!/usr/bin/env python3
"""Runner resiliente da suite do Redoubt.

Isola CADA arquivo de teste num processo e tolera o crash flaky de teardown do Qt
offscreen (exit 0xC0000005 no shutdown do interpretador): se o junit XML nao sair,
re-tenta 1x. Soma os resultados e sai != 0 se qualquer teste falhar/erro — entao
serve tanto para rodar a suite a mao quanto como guarda do hook git `pre-push`.

Uso:
    python tools/run_tests.py            # roda toda a suite (tests/test_*.py)

Sem dependencias alem de pytest (e do que os testes ja usam).
"""

from __future__ import annotations

import glob
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.join(ROOT, "tests")


def _run_once(test_path: str, xml_path: str) -> None:
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONIOENCODING="utf-8")
    subprocess.run(
        [sys.executable, "-m", "pytest", test_path, "-q", "-p", "no:cacheprovider",
         "--junitxml", xml_path],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _has_xml(path: str) -> bool:
    return os.path.exists(path) and os.path.getsize(path) > 0


def _parse(xml_path: str) -> tuple[int, int, int]:
    root = ET.parse(xml_path).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    return (int(suite.get("tests", 0)), int(suite.get("failures", 0)),
            int(suite.get("errors", 0)))


def main() -> int:
    files = sorted(glob.glob(os.path.join(TESTS_DIR, "test_*.py")))
    if not files:
        print("Nenhum teste encontrado em tests/.")
        return 1

    print("Rodando a suite do Redoubt (isolada por arquivo, offscreen)...\n")
    total = fails = errs = 0
    bad: list[str] = []
    for path in files:
        name = os.path.basename(path)
        fd, xml_path = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        try:
            _run_once(path, xml_path)
            if not _has_xml(xml_path):
                _run_once(path, xml_path)          # retry: crash de teardown do Qt
            if not _has_xml(xml_path):
                print(f"  [!] {name:<26} sem XML apos retry")
                bad.append(name)
                continue
            t, f, e = _parse(xml_path)
            total += t
            fails += f
            errs += e
            if f + e:
                bad.append(name)
            print(f"  {'FALHOU' if f + e else 'ok':<6} {name:<26} {t:>3} testes")
        finally:
            try:
                os.remove(xml_path)
            except OSError:
                pass

    print(f"\nTOTAL {total} | falhas {fails} | erros {errs}")
    if bad:
        print("FALHOU: " + ", ".join(bad))
        return 1
    print("TODOS VERDES")
    return 0


if __name__ == "__main__":
    sys.exit(main())
