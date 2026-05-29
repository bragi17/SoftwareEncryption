[CmdletBinding()]
param(
    [string]$GradlePath = "",
    [string]$VendorPublicKeySha256 = "",
    [switch]$SkipRust,
    [switch]$SkipJava,
    [switch]$SkipPyInstaller,
    [switch]$SkipStudio
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$ProtectSpecPath = Join-Path $RepoRoot "packaging\pyinstaller\skey-protect.spec"
$StudioSpecPath = Join-Path $RepoRoot "packaging\pyinstaller\skey-studio.spec"
$DistRoot = Join-Path $RepoRoot "dist"
$ProtectExePath = Join-Path $RepoRoot "dist\skey-protect.exe"
$StudioExePath = Join-Path $RepoRoot "dist\skey-studio.exe"
$RuntimePinSha256 = $null

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message"
}

function Invoke-Checked {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory = $RepoRoot
    )

    Write-Host "+ $FilePath $($Arguments -join ' ')"
    Push-Location $WorkingDirectory
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "command failed with exit code ${LASTEXITCODE}: $FilePath"
        }
    }
    finally {
        Pop-Location
    }
}

function Get-Cargo {
    $cargo = Get-Command "cargo" -ErrorAction SilentlyContinue
    if ($null -ne $cargo) {
        return $cargo.Source
    }

    $cargoHome = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (Test-Path $cargoHome) {
        $env:Path = "$(Split-Path $cargoHome);$env:Path"
        return $cargoHome
    }

    throw "cargo was not found on PATH or at $cargoHome"
}

function Resolve-VendorPublicKeyPin {
    $pin = $VendorPublicKeySha256
    if (-not $pin) {
        $pin = $env:SKEY_VENDOR_PUBLIC_KEY_SHA256
    }
    if (-not $pin) {
        throw "SKEY_VENDOR_PUBLIC_KEY_SHA256 is required when building release runtime artifacts. Pass -VendorPublicKeySha256 or set the environment variable."
    }

    $normalized = $pin.Trim()
    if ($normalized.StartsWith("sha256:", [System.StringComparison]::OrdinalIgnoreCase)) {
        $normalized = $normalized.Substring(7)
    }
    $normalized = $normalized.ToLowerInvariant()
    if ($normalized -notmatch "^[0-9a-f]{64}$") {
        throw "Vendor public key pin must be a lowercase sha256 hex digest or sha256:<hex>"
    }
    $env:SKEY_VENDOR_PUBLIC_KEY_SHA256 = $normalized
    return $normalized
}

function Get-Gradle {
    if ($GradlePath) {
        $resolved = (Resolve-Path $GradlePath).Path
        if (-not (Test-Path $resolved)) {
            throw "GradlePath does not exist: $GradlePath"
        }
        return $resolved
    }

    $repoGradle = Join-Path $RepoRoot "java\skey-loader\gradlew.bat"
    if (Test-Path $repoGradle) {
        return $repoGradle
    }

    $gradle = Get-Command "gradle" -ErrorAction SilentlyContinue
    if ($null -ne $gradle) {
        return $gradle.Source
    }

    $tempGradle = Join-Path $env:TEMP "skey-gradle-tools\gradle-9.5.1\bin\gradle.bat"
    if (Test-Path $tempGradle) {
        return $tempGradle
    }

    throw "Gradle was not found. Pass -GradlePath, install gradle on PATH, or place gradle at $tempGradle"
}

function Ensure-VenvPython {
    if (Test-Path $VenvPython) {
        return
    }

    Write-Step "creating .venv"
    $py = Get-Command "py" -ErrorAction SilentlyContinue
    if ($null -ne $py) {
        Invoke-Checked $py.Source @("-3", "-m", "venv", ".venv")
        return
    }

    $python = Get-Command "python" -ErrorAction SilentlyContinue
    if ($null -eq $python) {
        throw "Python was not found; install Python 3.11+ or create .venv manually"
    }
    Invoke-Checked $python.Source @("-m", "venv", ".venv")
}

function Test-PythonModule {
    param([string]$ModuleName)

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $VenvPython -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('$ModuleName') else 1)" *> $null
        return $LASTEXITCODE -eq 0
    }
    finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
}

function Get-LockedPyInstallerPackages {
    $lockFile = Join-Path $RepoRoot "requirements-lock.txt"
    if (-not (Test-Path $lockFile)) {
        return @()
    }

    $packageNames = (
        "altgraph",
        "pefile",
        "pyinstaller",
        "pyinstaller-hooks-contrib",
        "pywin32-ctypes",
        "setuptools"
    )
    $pattern = "^(?i:($($packageNames -join '|')))=="
    return @(Get-Content $lockFile | Where-Object { $_ -match $pattern })
}

function Ensure-PyInstaller {
    Ensure-VenvPython
    if (Test-PythonModule "PyInstaller") {
        return
    }

    Write-Step "installing PyInstaller into .venv"
    $lockedPackages = @(Get-LockedPyInstallerPackages)
    if ($lockedPackages.Count -gt 0) {
        $pipArgs = @("-m", "pip", "install")
        $pipArgs += $lockedPackages
        Invoke-Checked $VenvPython $pipArgs
        return
    }

    Invoke-Checked $VenvPython @("-m", "pip", "install", "pyinstaller")
}

function Copy-RequiredFile {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (-not (Test-Path $Source)) {
        throw "required build artifact is missing: $Source"
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $Destination) | Out-Null
    Copy-Item -Force -LiteralPath $Source -Destination $Destination
}

function Copy-OptionalFile {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (-not (Test-Path $Source)) {
        return
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $Destination) | Out-Null
    Copy-Item -Force -LiteralPath $Source -Destination $Destination
}

function Copy-FirstOptionalFile {
    param(
        [string[]]$Sources,
        [string]$Destination
    )

    foreach ($source in $Sources) {
        if (Test-Path $source) {
            Copy-OptionalFile $source $Destination
            return
        }
    }
}

function Publish-ToolArtifacts {
    Write-Step "publishing protector tool artifacts"
    New-Item -ItemType Directory -Force -Path $DistRoot | Out-Null
    Copy-RequiredFile `
        (Join-Path $RepoRoot "rust\target\release\skey_ffi.dll") `
        (Join-Path $DistRoot "skey_ffi.dll")
    Copy-RequiredFile `
        (Join-Path $RepoRoot "rust\target\release\skey-exe-shell.exe") `
        (Join-Path $DistRoot "skey-exe-shell.exe")
    Copy-RequiredFile `
        (Join-Path $RepoRoot "rust\target\release\skey_jni.dll") `
        (Join-Path $DistRoot "skey_jni.dll")
    Copy-RequiredFile `
        (Join-Path $RepoRoot "java\skey-loader\build\libs\skey-loader.jar") `
        (Join-Path $DistRoot "skey-loader.jar")
    Copy-FirstOptionalFile @(
        (Join-Path $RepoRoot "rust\target\release\libskey_ffi.so"),
        (Join-Path $RepoRoot "rust\target\x86_64-unknown-linux-gnu\release\libskey_ffi.so")
    ) (Join-Path $DistRoot "libskey_ffi.so")
    Copy-FirstOptionalFile @(
        (Join-Path $RepoRoot "rust\target\release\libskey_jni.so"),
        (Join-Path $RepoRoot "rust\target\x86_64-unknown-linux-gnu\release\libskey_jni.so")
    ) (Join-Path $DistRoot "libskey_jni.so")
    Copy-FirstOptionalFile @(
        (Join-Path $RepoRoot "rust\target\release\libskey_ffi.dylib"),
        (Join-Path $RepoRoot "rust\target\x86_64-apple-darwin\release\libskey_ffi.dylib"),
        (Join-Path $RepoRoot "rust\target\aarch64-apple-darwin\release\libskey_ffi.dylib")
    ) (Join-Path $DistRoot "libskey_ffi.dylib")
    Copy-FirstOptionalFile @(
        (Join-Path $RepoRoot "rust\target\release\libskey_jni.dylib"),
        (Join-Path $RepoRoot "rust\target\x86_64-apple-darwin\release\libskey_jni.dylib"),
        (Join-Path $RepoRoot "rust\target\aarch64-apple-darwin\release\libskey_jni.dylib")
    ) (Join-Path $DistRoot "libskey_jni.dylib")
    if ($script:RuntimePinSha256) {
        Set-Content `
            -Path (Join-Path $DistRoot "skey-runtime-pin.sha256") `
            -Value $script:RuntimePinSha256 `
            -Encoding ascii
    }
}

Set-Location $RepoRoot

if (-not $SkipRust) {
    Write-Step "building Rust release artifacts"
    $script:RuntimePinSha256 = Resolve-VendorPublicKeyPin
    $cargoPath = Get-Cargo
    Invoke-Checked $cargoPath @("build", "--release", "--manifest-path", "rust\Cargo.toml", "--workspace")
}
elseif ($env:SKEY_VENDOR_PUBLIC_KEY_SHA256) {
    $script:RuntimePinSha256 = Resolve-VendorPublicKeyPin
}

if (-not $SkipJava) {
    Write-Step "building Java loader JAR"
    $gradle = Get-Gradle
    Invoke-Checked $gradle @("-p", "java\skey-loader", "build")
}

Publish-ToolArtifacts

if (-not $SkipPyInstaller) {
    Write-Step "building skey-protect.exe"
    Ensure-PyInstaller
    Invoke-Checked $VenvPython @("-m", "PyInstaller", "--clean", "--noconfirm", $ProtectSpecPath)

    if (-not (Test-Path $ProtectExePath)) {
        throw "expected EXE was not created: $ProtectExePath"
    }

    Write-Host "Built $ProtectExePath"

    if (-not $SkipStudio) {
        Write-Step "building skey-studio.exe"
        Invoke-Checked $VenvPython @("-m", "PyInstaller", "--clean", "--noconfirm", $StudioSpecPath)

        if (-not (Test-Path $StudioExePath)) {
            throw "expected EXE was not created: $StudioExePath"
        }

        Write-Host "Built $StudioExePath"
    }
}
