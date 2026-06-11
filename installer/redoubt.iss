; ============================================================
;  Redoubt — instalador Windows (Inno Setup 6)
;  Compilar (da RAIZ do projeto):  ISCC.exe installer\redoubt.iss
;  Gera:  dist\Redoubt-Setup-<versao>.exe
;  Pre-requisito: dist\Redoubt.exe ja buildado (build.bat / PyInstaller).
; ============================================================

#define AppName "Redoubt"
#define AppVersion "1.0.0"
#define AppPublisher "Natan Lopes"
#define AppExe "Redoubt.exe"

[Setup]
AppId={{8F3E5B2A-1C4D-4E9F-A6B7-2D3C9E0F1A2B}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
; Os caminhos de Source/Output/Icon sao relativos a RAIZ do projeto:
SourceDir=..
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=dist
OutputBaseFilename=Redoubt-Setup-{#AppVersion}
SetupIconFile=assets\redoubt.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "pt"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na area de trabalho"; GroupDescription: "Atalhos:"
Name: "assocrdbt"; Description: "Associar arquivos .rdbt ao Redoubt (duplo-clique abre o cofre)"; GroupDescription: "Integracao:"

[Files]
Source: "dist\Redoubt.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Desinstalar {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Associacao do cofre .rdbt (so se a task estiver marcada). HKA = HKLM (admin) ou HKCU.
Root: HKA; Subkey: "Software\Classes\.rdbt"; ValueType: string; ValueName: ""; ValueData: "Redoubt.Vault"; Flags: uninsdeletevalue; Tasks: assocrdbt
Root: HKA; Subkey: "Software\Classes\Redoubt.Vault"; ValueType: string; ValueName: ""; ValueData: "Cofre cifrado do Redoubt"; Flags: uninsdeletekey; Tasks: assocrdbt
Root: HKA; Subkey: "Software\Classes\Redoubt.Vault\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExe},0"; Tasks: assocrdbt
Root: HKA; Subkey: "Software\Classes\Redoubt.Vault\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: assocrdbt

[Run]
Filename: "{app}\{#AppExe}"; Description: "Abrir o {#AppName} agora"; Flags: nowait postinstall skipifsilent
