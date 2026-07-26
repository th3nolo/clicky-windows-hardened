; REFERENCE ONLY — NOT A RELEASE PIPELINE.
; This installer must not compile until Authenticode signing and post-signature
; verification are implemented and reviewed.
#error "Installer build disabled: Authenticode signing pipeline is not implemented"

;  Clicky for Windows — reference-only Inno Setup script
;
;  COMPILATION IS INTENTIONALLY DISABLED ABOVE.
;  Do not remove the guard until a reviewed release pipeline signs and verifies
;  both Clicky.exe and Setup-Clicky.exe with Authenticode before distribution.

#define MyAppName        "Clicky"
#define MyAppVersion     "1.2.0"
#define MyAppPublisher   "Shashank Singh"
#define MyAppURL         "https://github.com/Bitshank-2338/clicky-windows"
#define MyAppExeName     "Clicky.exe"

[Setup]
AppId={{9A4E3F2C-7B1D-4A8F-9C6E-3D7F1B5E9A0C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=LICENSE
OutputDir=dist
OutputBaseFilename=Setup-Clicky
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
#if FileExists("assets\icon.ico")
  SetupIconFile=assets\icon.ico
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";  Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "startupicon";  Description: "Launch Clicky when Windows &starts";  GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; Everything PyInstaller produced
Source: "dist\Clicky\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}";                    Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}";          Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";              Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}";              Filename: "{app}\{#MyAppExeName}"; Tasks: startupicon

[Run]
; The hardened installer never downloads or executes third-party installers.
; Ollama and model provisioning are separate, user-directed steps.

; Offer to launch Clicky after install
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    MsgBox(
      'Clicky installed successfully!' #13#13
      'Clicky never downloads or executes Ollama or AI models.' #13
      'If you want local AI, install Ollama separately from its official site,' #13
      'verify the installer publisher, and provision reviewed models yourself.' #13#13
      'Credentials must be supplied by a trusted parent process or Windows' #13
      'environment. The bundled .env.example is reference-only and is never' #13
      'loaded by Clicky.',
      mbInformation, MB_OK
    );
  end;
end;
