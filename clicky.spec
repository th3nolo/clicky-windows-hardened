# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Clicky Windows.

Build:
    pyinstaller clicky.spec --clean --noconfirm

Output:
    dist/Clicky/Clicky.exe

SECURITY STATUS:
    LOCAL TEST ONLY — UNSIGNED — DO NOT DISTRIBUTE.
    Inno Setup packaging is disabled. The reviewed Store MSIX path consumes
    one separately preserved, commit-bound onedir after runtime validation.

We use --onedir (not --onefile) because faster-whisper and ctranslate2 ship
large native DLLs. A one-file build extracts those files to a temporary
directory at every launch, increasing startup time and transient-file surface.

Python modules are also collected as external bytecode instead of an embedded
PYZ archive. This keeps the executable payload inspectable and avoids presenting
antivirus engines with a large compressed-code overlay. The exact distribution
tree and its future signed installer must protect these external files.
"""

from PyInstaller.utils.hooks import collect_all, collect_submodules

# ── Modules that are lazy-imported by CompanionManager — PyInstaller's
#    static analysis misses them, so we list them explicitly.
hidden = [
    "automation.action_approval",
    "automation.action_broker",
    "automation.action_models",
    "automation.action_process",
    "automation.action_protocol",
    "automation.models",
    "automation.policy",
    "automation.review",
    "automation.stop",
    "automation.task_center",
    "automation.targeting",
    "automation.uia_actions",
    "automation.uia_worker",
    # Lazy LLM providers
    "ai.claude_provider",
    "ai.openai_provider",
    "ai.gemini_provider",
    "ai.openai_compatible_provider",
    "ai.provider_catalog",
    "ai.provider_factory",
    "ai.agent_cli_provider",
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
    "connectors.accounts",
    "connectors.base",
    "connectors.gmail",
    "connectors.google_calendar",
    "connectors.google_sheets",
    "connectors.google_slides",
    "connectors.notion",
    "connectors.oauth",
    "connectors.task_bridge",
    "connectors.token_store",
    "compose.insertion",
    "compose.models",
    "compose.prompt",
    "compose.region_context",
    "compose.service",
    "memory.style_profiles",
    "notion_contracts",
    "research.models",
    "research.csv_artifact",
    "research.markdown_artifact",
    "research.tools",
    "sheets_contracts",
    "slides_contracts",
    "skills.declarative_runner",
    "skills.registry",
    "skills.schema",
    "tasks.followup_context",
    "tasks.region_context",
    "walkthrough.models",
    "walkthrough.protocol",
    "walkthrough.controller",
    "walkthrough.prompt",

    # First-run setup wizard
    "ui.setup_wizard",
    "ui.onboarding_demo",
    "ui.microphone_test",
    "ui.walkthrough",
    "ui.stt_readiness",
    "ui.style_profiles",
    "ui.skills_catalog",
    "ui.task_center",
    "ui.connected_accounts",
    "ui.desktop_action_highlight",
    "ui.compose_preview",
    "ui.region_compose",
    "ui.region_handoff",
    "ui.region_task",
    "ui.task_followup",
    "ui.workspace_diff_review",
    "workspace_coding.adoption",
    "workspace_coding.broker",
    "workspace_coding.file_protection",
    "workspace_coding.models",
    "workspace_coding.paths",
    "workspace_coding.sandbox",
    "workspace_coding.snapshot",
    "handoff.image_capture",
    "handoff.routing",
    "handoff.selection",

    # Lazy STT providers
    "audio.stt.deepgram_stt",
    "audio.stt.deepgram_streaming",
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
    ("skills/declarative/manifest.json", "skills/declarative"),
    (
        "skills/declarative/research-to-csv.skill.json",
        "skills/declarative",
    ),
    (
        "skills/declarative/research-to-markdown.skill.json",
        "skills/declarative",
    ),
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
    "aiohttp",
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
hiddenimports += collect_submodules("tasks")


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
    noarchive=True,              # external bytecode; avoid an opaque PYZ payload
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
    manifest="clicky.manifest",
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
