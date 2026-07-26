@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM Safety boundary: this validator is destructive only inside Windows Sandbox.
REM A normal host invocation must stop before touching inputs or requesting shutdown.
if /I not "%USERNAME%"=="WDAGUtilityAccount" (
    echo [FAIL] This validator may run only as the Windows Sandbox account.
    exit /b 4
)

set "INPUT=C:\ClickyInput"
set "WORK=C:\ClickyWork"
set "OUTPUT=C:\ValidationOutput"
set "PYTHON_ROOT=C:\Python312"
set "PYTHON=%PYTHON_ROOT%\python.exe"
set "PYTHON_ZIP=%INPUT%\python-runtime.zip"
set "UV=%INPUT%\uv.exe"
set "LOG=%OUTPUT%\sandbox-validation.log"
set "RESULT=1"

if not exist "%OUTPUT%" (
    call :shutdown_if_sandbox
    exit /b 2
)
for /f "delims=" %%F in ('dir /b /a "%OUTPUT%" 2^>nul') do (
    echo [FAIL] Refusing a non-empty validation output directory.
    call :shutdown_if_sandbox
    exit /b 3
)
> "%LOG%" echo Clicky Windows Sandbox validation started

for %%F in (clicky-source.zip source-commit.txt source-archive-sha256.txt uv.exe uv-sha256.txt python-runtime.zip python-runtime-sha256.txt windows-sandbox-validate.cmd) do (
    if not exist "%INPUT%\%%F" (
        >> "%LOG%" echo [FAIL] Required reviewed input is missing: %%F
        goto :finish
    )
)

set "ACTUAL_SOURCE_SHA256="
for /f "tokens=*" %%H in ('certutil.exe -hashfile "%INPUT%\clicky-source.zip" SHA256 ^| findstr.exe /R /X "[0-9a-fA-F][0-9a-fA-F]*"') do if not defined ACTUAL_SOURCE_SHA256 set "ACTUAL_SOURCE_SHA256=%%H"
set /p EXPECTED_SOURCE_SHA256=<"%INPUT%\source-archive-sha256.txt"
if /I not "!ACTUAL_SOURCE_SHA256!"=="!EXPECTED_SOURCE_SHA256!" (
    >> "%LOG%" echo [FAIL] Source archive SHA-256 mismatch.
    goto :finish
)
set "ACTUAL_UV_SHA256="
for /f "tokens=*" %%H in ('certutil.exe -hashfile "%UV%" SHA256 ^| findstr.exe /R /X "[0-9a-fA-F][0-9a-fA-F]*"') do if not defined ACTUAL_UV_SHA256 set "ACTUAL_UV_SHA256=%%H"
set /p EXPECTED_UV_SHA256=<"%INPUT%\uv-sha256.txt"
if /I not "!ACTUAL_UV_SHA256!"=="!EXPECTED_UV_SHA256!" (
    >> "%LOG%" echo [FAIL] uv SHA-256 mismatch.
    goto :finish
)
set "ACTUAL_PYTHON_SHA256="
for /f "tokens=*" %%H in ('certutil.exe -hashfile "%PYTHON_ZIP%" SHA256 ^| findstr.exe /R /X "[0-9a-fA-F][0-9a-fA-F]*"') do if not defined ACTUAL_PYTHON_SHA256 set "ACTUAL_PYTHON_SHA256=%%H"
set /p EXPECTED_PYTHON_SHA256=<"%INPUT%\python-runtime-sha256.txt"
if /I not "!ACTUAL_PYTHON_SHA256!"=="!EXPECTED_PYTHON_SHA256!" (
    >> "%LOG%" echo [FAIL] Python runtime archive SHA-256 mismatch.
    goto :finish
)

if exist "%PYTHON_ROOT%" (
    >> "%LOG%" echo [FAIL] Refusing to reuse C:\Python312.
    goto :finish
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command "Expand-Archive -LiteralPath '%PYTHON_ZIP%' -DestinationPath '%PYTHON_ROOT%'" >> "%LOG%" 2>&1
if errorlevel 1 (
    >> "%LOG%" echo [FAIL] Reviewed Python runtime extraction failed.
    goto :finish
)
if not exist "%PYTHON%" (
    >> "%LOG%" echo [FAIL] Reviewed Python executable is missing after extraction.
    goto :finish
)

set "PATH=%PYTHON_ROOT%;%INPUT%;%SystemRoot%\System32;%SystemRoot%"
set "PYTHONNOUSERSITE=1"
set "PYTHONDONTWRITEBYTECODE=1"
set "CLICKY_WINDOWS_SANDBOX=1"
set "UV_PYTHON_DOWNLOADS=never"
set "UV_NO_CACHE=1"
set "UV_DEFAULT_INDEX=https://pypi.org/simple"
set "UV_INDEX_STRATEGY=first-index"
set "UV_KEYRING_PROVIDER=disabled"
set "PIP_INDEX_URL="
set "PIP_EXTRA_INDEX_URL="
set "PIP_FIND_LINKS="
set "ANTHROPIC_API_KEY="
set "OPENAI_API_KEY="
set "GOOGLE_API_KEY="
set "GEMINI_API_KEY="
set "DEEPGRAM_API_KEY="
set "ELEVENLABS_API_KEY="
set "TAVILY_API_KEY="
set "HTTP_PROXY="
set "HTTPS_PROXY="
set "ALL_PROXY="
set "NO_PROXY="
set "UV_INDEX="
set "UV_INDEX_URL="
set "UV_EXTRA_INDEX_URL="
set "UV_FIND_LINKS="

for /f "tokens=2" %%V in ('"%PYTHON%" --version 2^>^&1') do set "PYTHON_VERSION=%%V"
for /f "tokens=2" %%V in ('"%UV%" --version 2^>^&1') do set "UV_VERSION=%%V"
>> "%LOG%" echo Python !PYTHON_VERSION!
>> "%LOG%" echo uv !UV_VERSION!
if not "!PYTHON_VERSION!"=="3.12.10" (
    >> "%LOG%" echo [FAIL] Python version mismatch.
    goto :finish
)
if not "!UV_VERSION!"=="0.11.19" (
    >> "%LOG%" echo [FAIL] uv version mismatch.
    goto :finish
)

if exist "%WORK%" (
    >> "%LOG%" echo [FAIL] Refusing to reuse C:\ClickyWork.
    goto :finish
)
mkdir "%WORK%" || goto :finish
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command "Expand-Archive -LiteralPath '%INPUT%\clicky-source.zip' -DestinationPath '%WORK%'" >> "%LOG%" 2>&1
if errorlevel 1 (
    >> "%LOG%" echo [FAIL] Reviewed source archive extraction failed.
    goto :finish
)
if not exist "%WORK%\pyproject.toml" (
    >> "%LOG%" echo [FAIL] Extracted source is incomplete.
    goto :finish
)
fc.exe /b "%INPUT%\windows-sandbox-validate.cmd" "%WORK%\tools\windows-sandbox-validate.cmd" >nul
if errorlevel 1 (
    >> "%LOG%" echo [FAIL] Bootstrap validator does not match the archived source.
    goto :finish
)
cd /d "%WORK%" || goto :finish

>> "%LOG%" echo [1/7] Checking lock offline
"%UV%" lock --check --offline --no-build --no-sources --no-python-downloads --python "%PYTHON%" >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [2/7] Verifying live PyPI provenance
"%PYTHON%" tools\check_dependency_policy.py --verify-pypi >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [3/7] Creating frozen validation environment
"%UV%" sync --frozen --group build --no-build --no-managed-python --no-python-downloads --python "%PYTHON%" --default-index "https://pypi.org/simple" --index-strategy first-index --keyring-provider disabled --link-mode copy --no-cache >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [4/7] Running tests and compile validation
"%UV%" run --frozen --no-sync --python "%PYTHON%" python -W error -m unittest discover -s tests -p "test_*.py" -v >> "%LOG%" 2>&1
if errorlevel 1 goto :finish
"%UV%" run --frozen --no-sync --python "%PYTHON%" python -W error -m compileall -q ai audio screen skills tools ui companion_manager.py config.py main.py packaged_self_test.py >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [5/7] Building unsigned local-test artifact
call build.bat >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [6/7] Running Windows runtime controls
"%UV%" run --frozen --no-sync --python "%PYTHON%" python tools\windows_runtime_validation.py --output "%OUTPUT%\runtime-validation.json" >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [7/7] Recording source and artifact identity
copy /y "%INPUT%\source-commit.txt" "%OUTPUT%\source-commit.txt" >nul
if errorlevel 1 goto :finish
> "%OUTPUT%\source-archive-sha256.txt" echo !ACTUAL_SOURCE_SHA256!
certutil.exe -hashfile "dist\Clicky\Clicky.exe" SHA256 > "%OUTPUT%\clicky-exe-sha256.txt" 2>> "%LOG%"
if errorlevel 1 goto :finish

set "RESULT=0"

:finish
if "%RESULT%"=="0" (
    >> "%LOG%" echo [PASS] Windows Sandbox validation completed.
    > "%OUTPUT%\PASS.txt" echo PASS
) else (
    >> "%LOG%" echo [FAIL] Windows Sandbox validation stopped.
    > "%OUTPUT%\FAIL.txt" echo FAIL
)
call :shutdown_if_sandbox
exit /b %RESULT%

:shutdown_if_sandbox
if /I "%USERNAME%"=="WDAGUtilityAccount" (
    shutdown.exe /s /t 5 >nul 2>&1
) else (
    echo [WARN] Shutdown skipped outside Windows Sandbox.
)
exit /b 0
