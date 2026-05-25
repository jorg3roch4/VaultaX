# Skill Registry — VaultaX

## Project Conventions

- `AGENTS.md` — Project structure, source layout, stack summary
- `CLAUDE.md` — Build/test commands, constraints (net10, LangVersion 14, TreatWarningsAsErrors, no implicit usings, strict)
- `Directory.Build.props` — Authoritative build settings shared across all projects

## Compact Rules (inject into sub-agent prompts)

### .NET / C# (always apply)

- Target: **net10.0**, **LangVersion 14**
- `Nullable: enable` — no `null!` unless unavoidable, prefer `?` nullability annotations
- `ImplicitUsings: disable` — EVERY `using` must be explicit (top of file)
- `TreatWarningsAsErrors: true` — zero warnings, zero XML doc warnings
- `Features: strict`
- `GenerateDocumentationFile: true` — all public members need XML docs
- Use file-scoped namespaces
- Use `sealed` on classes unless inheritance is needed
- Primary constructors OK (already used)
- `ConfigureAwait(false)` on all awaits in library code

### Testing (always apply)

- Framework: **xUnit v3** (3.2.2) + **Moq** (4.20.72) + **FluentAssertions** (8.8.0) + **coverlet**
- Test runner: `dotnet test VaultaX.sln`
- Pattern: Arrange / Act / Assert with comments
- Mock `IVaultClient` via `VaultMockHelper.CreateMockVaultClient()` — existing helper
- Use `.Should().Be(...)`, `.Should().Throw<>()`, etc. — FluentAssertions style
- Test naming: `MethodName_Condition_ExpectedOutcome`

### Package management

- Add new deps to `VaultaX.csproj` only if truly needed. Prefer BCL.
- When touching `VaultaX.csproj`, bump `Version/AssemblyVersion/FileVersion` and update `PackageReleaseNotes`.
- Every release → CHANGELOG.md entry in reverse chronological order with `## [X.Y.Z] - YYYY-MM-DD`.

### VaultaX patterns

- Secret engines: `ISecretEngine` base → `IKeyValueEngine` / `ITransitEngine` / `IPkiEngine` (all in `Abstractions/ISecretEngine.cs`)
- Engines go under `Engines/{Name}/` (e.g., `Engines/Transit/TransitEngine.cs`)
- Models live alongside interface in the Abstractions file (existing convention — do NOT split into separate files)
- Access VaultSharp via `_vaultClient.GetUnderlyingClient()` for covered ops
- Exceptions: `VaultTransitException`, etc., under `Exceptions/`
- Structured logging via `ILogger<T>?` (optional), `_logger?.LogDebug/LogInformation/LogError`

### User skills (from `~/.claude/skills/`)

- `commit` — Conventional Commits with semantic versioning (not used inside this lib's repo)
- `caveman/*` — Communication compression (orthogonal)
- `go-testing`, `skill-creator` — N/A for this project
- `engram/memory` — Memory protocol, active always

### DO NOT

- Do NOT add `using` implicitly
- Do NOT introduce warnings (builds fail)
- Do NOT split existing multi-type files (ISecretEngine.cs) unless explicitly asked
- Do NOT break VaultSharp 1.17.5.1 abstraction for operations already covered by VaultSharp — only use raw HTTP for endpoints VaultSharp does not expose
