# Install project-scoped Agent Skills for Codex and Claude Code.
# Security: run only when you trust the upstream repositories; third-party
# instructions and scripts are NOT executed by the Portline build process.
param([ValidateSet('codex','claude-code')][string]$Agent='codex')
$ErrorActionPreference='Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Install Node.js 22.20+ first: https://nodejs.org/' }
$nodeVersion=(& node -v).TrimStart('v').Split('.')
if (([int]$nodeVersion[0] -lt 22) -or (([int]$nodeVersion[0] -eq 22) -and ([int]$nodeVersion[1] -lt 20))) {
    throw 'The current Skills CLI needs Node.js 22.20+.'
}
if (-not (Get-Command npx -ErrorAction SilentlyContinue)) { throw 'npx is missing from PATH.' }
$skills=@(
  @('vercel-labs/agent-skills','web-design-guidelines'),
  @('vercel-labs/agent-skills','writing-guidelines'),
  @('mattpocock/skills','code-review'),
  @('mattpocock/skills','diagnosing-bugs'),
  @('mattpocock/skills','tdd'),
  @('anthropics/skills','webapp-testing'),
  @('anthropics/skills','frontend-design'),
  @('Leonxlnx/taste-skill','design-taste-frontend')
)
foreach ($entry in $skills) {
  Write-Host ('[SKILL] '+$entry[0]+' / '+$entry[1])
  & npx --yes skills@latest add $entry[0] --skill $entry[1] --agent $Agent --copy --yes
  if ($LASTEXITCODE -ne 0) { throw ('Could not install '+$entry[0]+' / '+$entry[1]) }
}
Write-Host '[OK] Project skills installed. Review .agents/skills and skills-lock.json before committing.'
Write-Host 'The repository vercel-labs/skills is the installer CLI itself; it is used via npx, not installed as a skill.'
