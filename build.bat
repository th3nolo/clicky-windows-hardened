@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0" || exit /b 1

REM Clicky Windows hardened build.
REM This build is intentionally fail-closed:
REM   - uv and Python versions are pinned.
REM   - uv.lock must already be current.
REM   - only PyPI wheels from the frozen lock may be installed.
REM   - no pip, source builds, Git/path dependencies, or package upgrades.

set "EXPECTED_UV_VERSION=0.11.19"
set "EXPECTED_PYTHON_VERSION=3.12.10"
set "PYPI_INDEX=https://pypi.org/simple"
set "RESULT=1"

if /I "%~1"=="installer" (
    echo [ERROR] Installer builds are disabled.
    echo An Authenticode signing and verification pipeline does not exist yet.
    echo build.bat produces an unsigned LOCAL TEST ONLY portable artifact.
    goto :cleanup
)
if not "%~1"=="" (
    echo [ERROR] Unknown argument: %~1
    echo Usage: build.bat
    goto :cleanup
)

where uv.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] uv %EXPECTED_UV_VERSION% is required on PATH.
    echo Install that reviewed version from the official uv release, then retry.
    goto :cleanup
)

for /f "tokens=2" %%V in ('uv --version 2^>nul') do set "FOUND_UV_VERSION=%%V"
if not "!FOUND_UV_VERSION!"=="%EXPECTED_UV_VERSION%" (
    echo [ERROR] Expected uv %EXPECTED_UV_VERSION%, found !FOUND_UV_VERSION!.
    echo Refusing to build with a different dependency toolchain.
    goto :cleanup
)

if not exist "pyproject.toml" (
    echo [ERROR] pyproject.toml is missing.
    goto :cleanup
)
if not exist "uv.lock" (
    echo [ERROR] uv.lock is missing.
    goto :cleanup
)
if not exist "clicky.spec" (
    echo [ERROR] clicky.spec is missing.
    goto :cleanup
)
if exist "build" (
    echo [ERROR] build\ already exists. Inspect and remove it before rebuilding.
    goto :cleanup
)
if exist "dist" (
    echo [ERROR] dist\ already exists. Inspect and remove it before rebuilding.
    goto :cleanup
)

REM Ignore dependency-related environment overrides inherited from the caller.
set "UV_INDEX="
set "UV_EXTRA_INDEX_URL="
set "UV_INDEX_URL="
set "UV_FIND_LINKS="
set "UV_DEFAULT_INDEX=%PYPI_INDEX%"
set "UV_INDEX_STRATEGY=first-index"
set "UV_KEYRING_PROVIDER=disabled"
set "UV_NO_BUILD=1"
set "UV_PYTHON_DOWNLOADS=never"
set "PIP_INDEX_URL="
set "PIP_EXTRA_INDEX_URL="
set "PIP_FIND_LINKS="

echo [1/6] Verifying the frozen lock without network access...
uv lock --check --offline --no-build --no-sources --no-python-downloads --python "%EXPECTED_PYTHON_VERSION%"
if errorlevel 1 (
    echo [ERROR] uv.lock does not match pyproject.toml.
    goto :cleanup
)

set "UV_PROJECT_ENVIRONMENT=%TEMP%\clicky-build-%RANDOM%-%RANDOM%"
if exist "!UV_PROJECT_ENVIRONMENT!" (
    echo [ERROR] Refusing to reuse an existing temporary build environment.
    goto :cleanup
)

echo [2/6] Creating an isolated environment from reviewed wheels...
uv sync --frozen --group build --no-build --no-managed-python --no-python-downloads --python "%EXPECTED_PYTHON_VERSION%" --default-index "%PYPI_INDEX%" --index-strategy first-index --keyring-provider disabled --link-mode copy --no-cache
if errorlevel 1 (
    echo [ERROR] Frozen wheel-only dependency sync failed.
    goto :cleanup
)

echo [3/6] Generating the deterministic application icon...
uv run --frozen --no-sync --python "%EXPECTED_PYTHON_VERSION%" python "assets\make_icon.py"
if errorlevel 1 (
    echo [ERROR] Icon generation failed.
    goto :cleanup
)

echo [4/6] Building the portable application...
uv run --frozen --no-sync --python "%EXPECTED_PYTHON_VERSION%" python -m PyInstaller "clicky.spec" --clean
if errorlevel 1 (
    echo [ERROR] PyInstaller build failed.
    goto :cleanup
)

if not exist "dist\Clicky\Clicky.exe" (
    echo [ERROR] Expected output dist\Clicky\Clicky.exe was not created.
    goto :cleanup
)

echo [5/6] Bundling attribution and dependency evidence...
copy /y ".env.example" "dist\Clicky\.env.example" >nul
copy /y "LICENSE" "dist\Clicky\LICENSE" >nul
copy /y "README.md" "dist\Clicky\README.md" >nul
copy /y "pyproject.toml" "dist\Clicky\pyproject.toml" >nul
copy /y "uv.lock" "dist\Clicky\uv.lock" >nul
uv export --frozen --no-dev --no-emit-project --format cyclonedx1.5 --output-file "dist\Clicky\sbom.cdx.json"
if errorlevel 1 (
    echo [ERROR] CycloneDX SBOM generation failed.
    goto :cleanup
)

for /f "tokens=*" %%H in ('certutil.exe -hashfile "dist\Clicky\Clicky.exe" SHA256 ^| findstr.exe /R /X "[0-9a-fA-F][0-9a-fA-F]*"') do if not defined CLICKY_SHA256 set "CLICKY_SHA256=%%H"
if not defined CLICKY_SHA256 (
    echo [ERROR] Could not calculate the executable SHA-256.
    goto :cleanup
)
> "dist\Clicky\SHA256SUMS.txt" echo !CLICKY_SHA256!  Clicky.exe
> "dist\Clicky\UNSIGNED-LOCAL-TEST-ONLY.txt" (
    echo UNSIGNED LOCAL TEST ARTIFACT
    echo.
    echo DO NOT DISTRIBUTE OR REPRESENT THIS BUILD AS A RELEASE.
    echo It has not been Authenticode-signed or verified by a release pipeline.
    echo Rebuild through the future signing pipeline before any distribution.
)

echo [6/6] Unsigned portable local-test build complete.

set "RESULT=0"
echo.
echo ================================================================
echo   LOCAL TEST ONLY - UNSIGNED - DO NOT DISTRIBUTE
echo ================================================================
echo Output: dist\Clicky\Clicky.exe
echo SHA-256: !CLICKY_SHA256!
goto :cleanup
:cleanup
if defined UV_PROJECT_ENVIRONMENT if exist "!UV_PROJECT_ENVIRONMENT!" (
    rmdir /s /q "!UV_PROJECT_ENVIRONMENT!"
)
exit /b !RESULT!
