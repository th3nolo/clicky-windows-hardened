# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Clicky Windows.

Build:
    pyinstaller clicky.spec --clean --noconfirm

Output:
    dist/Clicky/Clicky.exe

SECURITY STATUS:
    LOCAL TEST ONLY — UNSIGNED — DO NOT DISTRIBUTE.
    Installer packaging is disabled until an Authenticode signing and
    post-signature verification pipeline is implemented.

We use --onedir (not --onefile) because faster-whisper and ctranslate2 ship
large native DLLs. A one-file build extracts those files to a temporary
directory at every launch, increasing startup time and transient-file surface.
"""

from PyInstaller.utils.hooks import collect_all, collect_submodules

# ── Modules that are lazy-imported by CompanionManager — PyInstaller's
#    static analysis misses them, so we list them explicitly.
hidden = [
    # Lazy LLM providers
    "ai.claude_provider",
    "ai.openai_provider",
    "ai.gemini_provider",
    "ai.ollama_provider",
    "ai.ollama_models_registry",
    "ai.github_copilot_provider",
    "ai.element_locator",
    "ai.universal_locator",
    "ai.web_search",
    "ai.ollama_bootstrap",
    "ai.lmstudio_provider",
    "ai.hybrid_pointer",
    "ai.figure_detector",

    # First-run setup wizard
    "ui.setup_wizard",

    # Lazy STT providers
    "audio.stt.deepgram_stt",
    "audio.stt.openai_stt",
    "audio.stt.faster_whisper_stt",
    "audio.stt.whisper_cpp_stt",

    # Lazy TTS providers
    "audio.tts.edge_tts_provider",
    "audio.tts.openai_tts_provider",
    "audio.tts.elevenlabs_provider",

]

# ── Heavy packages that ship non-Python assets (DLLs, JSON, voices).
#    collect_all grabs submodules + data files + binaries + metadata.
datas, binaries, hiddenimports = [], [], []
# Dynamically loaded bundled skills stay as source so their reviewed bytes can
# be verified against the shipped manifest before execution.
datas += [
    ("skills/example_self_mode.py", "skills"),
    ("skills/manifest.json", "skills"),
]
# Every package below is a pinned runtime dependency. Collection failures are
# fatal so a green build cannot silently omit an installed feature.
for pkg in (
    "faster_whisper",
    "ctranslate2",
    "tokenizers",
    "edge_tts",
    "anthropic",
    "openai",
    "httpx",
    "httpcore",
    "certifi",
    # Pointing + drawing accuracy stack (v1.2.0)
    "uiautomation",             # UIA tree walker (needs its bundled DLL)
    "rapidocr_onnxruntime",     # offline OCR — ships ONNX models as data
    "onnxruntime",
    "cv2",                      # figure detection for teaching drawings
    # Web search + misc runtime deps added since 1.1.x
    "imageio",
    "imageio_ffmpeg",
    "pypdf",
    "docx",
    "pywhispercpp",
):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

hiddenimports += hidden
hiddenimports += collect_submodules("PyQt6")


a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Shave size: Clicky never uses these heavy libs.
    excludes=[
        "matplotlib", "scipy", "pandas", "tkinter",
        "notebook", "jupyter", "IPython",
        "torch.distributions", "torch.onnx",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Clicky",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                    # keep binaries uncompressed and inspectable
    console=False,                # windowed local-test build
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/icon.ico" if __import__("os").path.exists("assets/icon.ico") else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Clicky",
)
