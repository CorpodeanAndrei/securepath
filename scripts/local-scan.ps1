# SecurePath — Local security scan (no AWS needed)
# Run: .\scripts\local-scan.ps1

Write-Host ""
Write-Host "  Running local security scans" -ForegroundColor Cyan

$tools = @("terraform", "tfsec", "checkov", "conftest")
foreach ($tool in $tools) {
    if (!(Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "  [MISSING] $tool" -ForegroundColor Yellow
    } else {
        Write-Host "  [OK] $tool found" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "  1. Terraform fmt check" -ForegroundColor Cyan
Push-Location "$PSScriptRoot\..\terraform"
terraform fmt -check -recursive
Pop-Location

Write-Host "  2. tfsec scan" -ForegroundColor Cyan
tfsec "$PSScriptRoot\..\terraform" --minimum-fail-severity HIGH

Write-Host "  3. Checkov scan" -ForegroundColor Cyan
checkov -d "$PSScriptRoot\..\terraform" --framework terraform --quiet

Write-Host "  4. OPA policy check" -ForegroundColor Cyan
conftest test "$PSScriptRoot\..\terraform" --policy "$PSScriptRoot\..\policies\opa"

Write-Host ""
Write-Host "  Scan complete" -ForegroundColor Green
