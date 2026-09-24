# Pacote Arch (Arch, CachyOS, Manjaro, EndeavourOS...)

O `PKGBUILD` depende só de pacotes dos repositórios oficiais (`python`, `python-pyqt6`,
`python-qscintilla-qt6`, `python-cryptography`): nada de `pip`. O código fica em
`/usr/lib/redoubt`, fora do `site-packages`, então uma troca de versão do Python no Arch não quebra
o pacote. O `check()` roda a suíte inteira, com o diretório de dados e as preferências isolados,
sem tocar nas chaves de quem compila.

O que o pacote instala:

| Caminho | O quê |
|---|---|
| `/usr/bin/redoubt` | o editor |
| `/usr/bin/redoubt-scan` | Sentinela na linha de comando e hook git (`--install-hook`) |
| `/usr/bin/redoubt-backup-identity` | backup/restauração da identidade (`docs/CUSTODY.md`) |
| `/usr/bin/redoubt-verify-release`, `redoubt-verify-seal` | verificadores standalone |
| `/usr/share/applications/redoubt.desktop` | entrada no menu, "Abrir com" |
| `/usr/share/mime/packages/redoubt.xml` | tipo `application/x-redoubt-vault` (`*.rdbt`) |

Os dados do usuário (identidade, trilha de auditoria, lista de redação) ficam em
`~/.local/share/Redoubt/Redoubt` (ou `$XDG_DATA_HOME`), com permissão `0700`. As preferências
ficam em `~/.config/Redoubt/Redoubt.conf`.

## Compilar e instalar a partir deste repositório

```bash
cd packaging/arch
makepkg -si
```

Para testar antes de existir a tag, troque o `source=` por um tarball local
(`git archive --prefix=Redoubt-1.4.0/ -o redoubt-1.4.0.tar.gz HEAD`, na raiz).

## Publicar no AUR (a cada release)

O nome `redoubt` estava livre no AUR em 2026-09-24.

1. Publique a tag `vX.Y.Z` no GitHub (o `source=` baixa `archive/refs/tags/vX.Y.Z.tar.gz`).
2. Atualize `pkgver` (e volte `pkgrel=1`), depois preencha o hash e regenere o `.SRCINFO`:
   ```bash
   updpkgsums
   makepkg --printsrcinfo > .SRCINFO
   ```
3. Confira o pacote: `makepkg -f && namcap PKGBUILD *.pkg.tar.zst`.
4. Envie para o repositório do AUR (precisa de conta e chave SSH cadastrada no AUR):
   ```bash
   git clone ssh://aur@aur.archlinux.org/redoubt.git aur-redoubt
   cp PKGBUILD .SRCINFO aur-redoubt/
   cd aur-redoubt && git add PKGBUILD .SRCINFO && git commit -m "redoubt X.Y.Z" && git push
   ```

Depois disso, quem usa CachyOS/Manjaro/Arch instala com `paru -S redoubt` ou `yay -S redoubt`
(no Manjaro, também pelo Pamac com o AUR habilitado).

### Avisos do `namcap` que são esperados

- `Referenced python module 'notepy.*' is an uninstalled dependency`: são os módulos do próprio
  Redoubt, em `/usr/lib/redoubt`. O `namcap` só procura no `site-packages`.
- `Dependency included, but may not be needed ('python-qscintilla-qt6')`: é importado como
  `PyQt6.Qsci`, nome que o `namcap` não associa ao pacote.
- `Referenced library 'python3'` / `'sh'`: vêm dos shebangs e já são garantidos por `python` e
  pelo sistema base.

## Testado em

Arch Linux, CachyOS e Manjaro (containers Docker, 2026-09-24): `makepkg` com `check()` (460
testes), `namcap`, `pacman -U`, `desktop-file-validate`, tipo MIME no Qt/KDE e no GIO/GNOME, e o app
abrindo em X11 (Xvfb). Python 3.14.7, PyQt6 6.11.0, QScintilla 2.14.1, cryptography 50.0.1.
