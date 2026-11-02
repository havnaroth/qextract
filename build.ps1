# Builds dist\qextract.exe - one file, no Python needed on the target machine.
# Needs Python 3.11+ (py launcher) on the build machine only.
# The location database (local\location_database.csv, not in git) is compiled into
# qextract\sources first; without it the exe only knows the definitions passed with -s.
# Checks first (a finding stops the build): the tests (when the tests folder is here),
# ruff and bandit with the rules in pyproject.toml; afterwards the exe is scanned for the
# private strings in local\private_patterns.txt (when that file is here).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Invoke-Step([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
}

if (-not (Test-Path .venv)) { Invoke-Step py @('-3.11', '-m', 'venv', '.venv') }
$py = '.\.venv\Scripts\python.exe'
Invoke-Step $py @('-m', 'pip', 'install', '-q', '-r', 'requirements-dev.txt')
if (Test-Path tests) {
    Invoke-Step $py @('-m', 'unittest', 'discover', '-s', 'tests', '-q')
} else {
    Write-Warning 'No tests folder: building without running the tests.'
}
Invoke-Step $py @('-m', 'ruff', 'check', '.')
Invoke-Step $py @('-m', 'bandit', '-q', '-c', 'pyproject.toml', '-r', 'qextract')
if (Test-Path tools\locations.py) { Invoke-Step $py @('tools\locations.py') }

$data = @()
if (Test-Path qextract\sources\*.json) {
    $data = @('--add-data', 'qextract\sources;qextract\sources')
} else {
    Write-Warning 'No location database compiled: the exe will have no built-in locations.'
}
Invoke-Step $py (@('-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--log-level', 'WARN',
    '--name', 'qextract', '--icon', 'quarantine-extractor.ico') + $data + @('run.py'))

if (Test-Path local\private_patterns.txt) {
    $found = Get-Content local\private_patterns.txt | Where-Object { $_.Trim() -and -not $_.StartsWith('#') } |
        Where-Object { Select-String -Path dist\qextract.exe -Pattern $_.Trim() -SimpleMatch -Quiet }
    if ($found) {
        Remove-Item dist\qextract.exe
        throw "The exe contains $(@($found).Count) private string(s) from local\private_patterns.txt - removed."
    }
}
Copy-Item THIRD-PARTY-NOTICES.md dist\ -Force
Get-Item dist\qextract.exe | Select-Object Name, Length, LastWriteTime
