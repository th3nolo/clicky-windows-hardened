@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SOURCE=C:\ClickySource"
set "WORK=C:\ClickyWork"
set "OUTPUT=C:\ValidationOutput"
set "PYTHON=C:\Python312\python.exe"
set "UV=C:\UvTool\uv.exe"
set "LOG=%OUTPUT%\sandbox-validation.log"
set "RESULT=1"

if not exist "%OUTPUT%" exit /b 2
> "%LOG%" echo Clicky Windows Sandbox validation started

if not exist "%PYTHON%" (
    >> "%LOG%" echo [FAIL] Reviewed Python executable is missing.
    goto :finish
)
if not exist "%UV%" (
    >> "%LOG%" echo [FAIL] Reviewed uv executable is missing.
    goto :finish
)

set "PATH=C:\Python312;C:\UvTool;%SystemRoot%\System32;%SystemRoot%"
set "PYTHONNOUSERSITE=1"
set "PYTHONDONTWRITEBYTECODE=1"
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
robocopy "%SOURCE%" "%WORK%" /E /COPY:DAT /R:1 /W:1 /XD .git .venv build dist __pycache__ /XF *.pyc >> "%LOG%" 2>&1
if errorlevel 8 (
    >> "%LOG%" echo [FAIL] Source copy failed.
    goto :finish
)
cd /d "%WORK%" || goto :finish

>> "%LOG%" echo [1/7] Checking lock offline
"%UV%" lock --check --offline --no-build --no-sources --no-python-downloads --python "3.12.10" >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [2/7] Verifying live PyPI provenance
"%PYTHON%" tools\check_dependency_policy.py --verify-pypi >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [3/7] Creating frozen validation environment
"%UV%" sync --frozen --group build --no-build --no-managed-python --no-python-downloads --python "3.12.10" --default-index "https://pypi.org/simple" --index-strategy first-index --keyring-provider disabled --link-mode copy --no-cache >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [4/7] Running tests and compile validation
"%UV%" run --frozen --no-sync --python "3.12.10" python -m unittest discover -s tests -p "test_*.py" -v >> "%LOG%" 2>&1
if errorlevel 1 goto :finish
"%UV%" run --frozen --no-sync --python "3.12.10" python -W error -m compileall -q . >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [5/7] Building unsigned local-test artifact
call build.bat >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [6/7] Running Windows runtime controls
"%UV%" run --frozen --no-sync --python "3.12.10" python tools\windows_runtime_validation.py --output "%OUTPUT%\runtime-validation.json" >> "%LOG%" 2>&1
if errorlevel 1 goto :finish

>> "%LOG%" echo [7/7] Recording source and artifact identity
git.exe -C "%SOURCE%" rev-parse HEAD > "%OUTPUT%\source-commit.txt" 2>> "%LOG%"
if errorlevel 1 (
    > "%OUTPUT%\source-commit.txt" echo uncommitted-sandbox-source
)
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
shutdown.exe /s /t 5 >nul 2>&1
exit /b %RESULT%
