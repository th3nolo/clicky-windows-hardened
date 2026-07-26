[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PythonRuntimeArchive,

    [Parameter(Mandatory = $true)]
    [string]$UvExe,

    [Parameter(Mandatory = $true)]
    [string]$GitExe,

    [string]$OutputRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExpectedPythonRuntimeSha256 = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
$ExpectedUvSha256 = "cd628b46729d01ad110146a647a633a6e5de0e091d73db46afaeee6fcb4ba648"
$ExpectedGitSha256 = "22fead8244ef3a7225fb800099a4e43eca8bcec0466774917669599c2f19a05a"
$ExpectedGitSignerThumbprint = "336C3F70E00092A477DCF6D5F44CE5E31E044C20"

function Assert-ReviewedFile {
    param([string]$Path, [string]$ExpectedSha256, [string]$Label)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must not be a reparse point or App Execution Alias: $Path"
    }
    if ($item.PSIsContainer) {
        throw "$Label must be a regular file: $Path"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) {
        throw "$Label SHA-256 mismatch. Expected $ExpectedSha256, found $actual"
    }
    return $item.FullName
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputRoot) {
    $workspaceRoot = Split-Path (Split-Path $repoRoot -Parent) -Parent
    $OutputRoot = Join-Path $workspaceRoot "outputs"
}
$outputRootPath = (Resolve-Path -LiteralPath $OutputRoot).Path
$repoPrefix = $repoRoot.TrimEnd("\") + "\"
$outputPrefix = $outputRootPath.TrimEnd("\") + "\"
if ($outputRootPath.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $repoRoot.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputRoot and the repository must not contain one another."
}

# Authenticate every candidate tool before its first execution. The Python ZIP
# is extracted only inside Windows Sandbox; neither Python nor uv is run here.
$PythonRuntimeArchive = Assert-ReviewedFile $PythonRuntimeArchive $ExpectedPythonRuntimeSha256 "Python runtime archive"
$UvExe = Assert-ReviewedFile $UvExe $ExpectedUvSha256 "uv"
$GitExe = Assert-ReviewedFile $GitExe $ExpectedGitSha256 "Git"
$gitSignature = Get-AuthenticodeSignature -LiteralPath $GitExe
if ($gitSignature.Status.ToString() -cne "Valid" -or
    $null -eq $gitSignature.SignerCertificate -or
    $gitSignature.SignerCertificate.Thumbprint -cne $ExpectedGitSignerThumbprint) {
    throw "Git Authenticode identity is not the reviewed signer."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$pythonZip = [IO.Compression.ZipFile]::OpenRead($PythonRuntimeArchive)
try {
    $pythonEntries = @($pythonZip.Entries)
    if ($pythonEntries.Count -eq 0) { throw "Python runtime archive is empty." }
    foreach ($entry in $pythonEntries) {
        $name = $entry.FullName
        if ($name -match "(^/|\\|(^|/)\.\.(/|$)|:)") {
            throw "Python runtime archive contains an unsafe path: $name"
        }
        $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
        if ($unixType -eq 0xA000) {
            throw "Python runtime archive contains a symbolic link: $name"
        }
    }
    $requiredPythonEntries = @("python.exe", "python312.dll", "python312.zip", "python312._pth")
    foreach ($required in $requiredPythonEntries) {
        if ($null -eq $pythonZip.GetEntry($required)) {
            throw "Python runtime archive is missing $required"
        }
    }
} finally {
    $pythonZip.Dispose()
}

$inheritedGitVariables = @(Get-ChildItem Env: | Where-Object { $_.Name -like "GIT_*" })
if ($inheritedGitVariables.Count -ne 0) {
    throw "Refusing inherited Git environment variables: $($inheritedGitVariables.Name -join ", ")"
}
$env:GIT_CONFIG_NOSYSTEM = "1"
$env:GIT_CONFIG_GLOBAL = "NUL"
$env:GIT_NO_REPLACE_OBJECTS = "1"

$gitBase = @(
    "--no-replace-objects",
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=NUL",
    "-c", "core.attributesFile=NUL",
    "-C", $repoRoot
)
$hooksPath = (& $GitExe --no-replace-objects -C $repoRoot config --local --get core.hooksPath 2>$null).ToString().Trim()
if ($LASTEXITCODE -ne 0 -or $hooksPath -ine "NUL") {
    throw "The repository must retain local core.hooksPath=NUL."
}
$gitDirectory = (& $GitExe @gitBase rev-parse --absolute-git-dir).ToString().Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $gitDirectory -PathType Container)) {
    throw "Could not resolve the repository Git directory."
}
foreach ($forbidden in @(
    (Join-Path $gitDirectory "objects\info\alternates"),
    (Join-Path $gitDirectory "info\grafts")
)) {
    if (Test-Path -LiteralPath $forbidden) {
        throw "Refusing Git object indirection: $forbidden"
    }
}
$replaceRefs = (@(& $GitExe @gitBase for-each-ref --format="%(refname)" refs/replace) -join "`n").Trim()
if ($LASTEXITCODE -ne 0 -or $replaceRefs) {
    throw "Refusing Git replace refs."
}
$status = (@(& $GitExe @gitBase status --porcelain=v1 --untracked-files=all) -join "`n").Trim()
if ($LASTEXITCODE -ne 0 -or $status) {
    throw "Refusing to snapshot a dirty or untracked working tree."
}
& $GitExe @gitBase fsck --full --strict --no-reflogs
if ($LASTEXITCODE -ne 0) { throw "Git object verification failed." }
$commit = (& $GitExe @gitBase rev-parse --verify "HEAD^{commit}").ToString().Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch "^[0-9a-f]{40}$") {
    throw "Could not resolve the exact source commit."
}

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$finalRunRoot = Join-Path $outputRootPath "windows-sandbox-$timestamp-$($commit.Substring(0, 12))"
if (Test-Path -LiteralPath $finalRunRoot) { throw "Run directory already exists: $finalRunRoot" }
$temporaryRunRoot = Join-Path $outputRootPath (".preparing-clicky-sandbox-" + [Guid]::NewGuid().ToString("N"))
$published = $false
try {
    $inputDirectory = Join-Path $temporaryRunRoot "input"
    $resultsDirectory = Join-Path $temporaryRunRoot "results"
    New-Item -ItemType Directory -Path $inputDirectory, $resultsDirectory | Out-Null

    $sourceArchive = Join-Path $inputDirectory "clicky-source.zip"
    & $GitExe @gitBase archive --format=zip --output=$sourceArchive $commit
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sourceArchive -PathType Leaf)) {
        throw "Could not create the commit-exact source archive."
    }

    # Extract the bootstrap from the archive itself so checkout line-ending
    # conversion cannot create a false binary mismatch.
    $sourceZip = [IO.Compression.ZipFile]::OpenRead($sourceArchive)
    try {
        $validatorEntry = $sourceZip.GetEntry("tools/windows-sandbox-validate.cmd")
        if ($null -eq $validatorEntry) { throw "Archived sandbox validator is missing." }
        $validatorOutput = Join-Path $inputDirectory "windows-sandbox-validate.cmd"
        $inputStream = $validatorEntry.Open()
        $outputStream = [IO.File]::Create($validatorOutput)
        try { $inputStream.CopyTo($outputStream) } finally {
            $outputStream.Dispose()
            $inputStream.Dispose()
        }
    } finally {
        $sourceZip.Dispose()
    }

    Copy-Item -LiteralPath $UvExe -Destination (Join-Path $inputDirectory "uv.exe")
    Copy-Item -LiteralPath $PythonRuntimeArchive -Destination (Join-Path $inputDirectory "python-runtime.zip")

    $ascii = [Text.Encoding]::ASCII
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceArchive).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $inputDirectory "source-commit.txt"), "$commit`n", $ascii)
    [IO.File]::WriteAllText((Join-Path $inputDirectory "source-archive-sha256.txt"), "$sourceHash`n", $ascii)
    [IO.File]::WriteAllText((Join-Path $inputDirectory "uv-sha256.txt"), "$ExpectedUvSha256`n", $ascii)
    [IO.File]::WriteAllText((Join-Path $inputDirectory "python-runtime-sha256.txt"), "$ExpectedPythonRuntimeSha256`n", $ascii)

    $finalInputDirectory = Join-Path $finalRunRoot "input"
    $finalResultsDirectory = Join-Path $finalRunRoot "results"
    $inputXml = [Security.SecurityElement]::Escape($finalInputDirectory)
    $resultsXml = [Security.SecurityElement]::Escape($finalResultsDirectory)
    $configuration = @"
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Default</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$inputXml</HostFolder>
      <SandboxFolder>C:\ClickyInput</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$resultsXml</HostFolder>
      <SandboxFolder>C:\ValidationOutput</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -Command "&amp; 'C:\ClickyInput\windows-sandbox-validate.cmd'; `$validationExit = `$LASTEXITCODE; `$shutdown = [IO.Path]::Combine(`$env:SystemRoot, 'System32', 'shutdown.exe'); &amp; `$shutdown /s /t 5 *&gt; `$null; if (`$LASTEXITCODE -ne 0) { exit 90 }; if (`$validationExit -ne 0) { exit `$validationExit }; Move-Item -LiteralPath 'C:\ValidationOutput\PASS.pending' -Destination 'C:\ValidationOutput\PASS.txt' -Force -ErrorAction Stop; exit 0"</Command>
  </LogonCommand>
</Configuration>
"@
    $wsbPath = Join-Path $temporaryRunRoot "clicky-hardened-validation.wsb"
    [IO.File]::WriteAllText($wsbPath, $configuration, [Text.UTF8Encoding]::new($false))

    Move-Item -LiteralPath $temporaryRunRoot -Destination $finalRunRoot
    $published = $true
} finally {
    if (-not $published -and (Test-Path -LiteralPath $temporaryRunRoot)) {
        Remove-Item -LiteralPath $temporaryRunRoot -Recurse -Force
    }
}

Write-Output "Commit: $commit"
Write-Output "Source archive SHA-256: $sourceHash"
Write-Output "uv SHA-256: $ExpectedUvSha256"
Write-Output "Python runtime SHA-256: $ExpectedPythonRuntimeSha256"
Write-Output "Results directory: $(Join-Path $finalRunRoot "results")"
Write-Output "Sandbox configuration: $(Join-Path $finalRunRoot "clicky-hardened-validation.wsb")"
