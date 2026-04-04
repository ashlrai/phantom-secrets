# Phantom Secrets — DX Enhancement Plan

## Context

Phantom Secrets (v0.4.0) has a solid security architecture: 5-crate Rust workspace, OS keychain + encrypted file vault, session-scoped proxy tokens, MCP server integration. The core cryptographic and proxy infrastructure is production-ready.

The gaps are all in **developer experience around the edges**: onboarding, multi-repo workflows, public key handling, reducing `phantom exec` friction, CI/CD integration, and pre-commit automation. These improvements will take Phantom from "solo dev installs it" to "team of 5 uses it daily without thinking about it."

This plan was developed from real-world usage of Phantom across two repos (Expo mobile app + Next.js web app) in a single coding session. Every item below emerged from actual friction encountered during that session.

---

## Phase 1: Public Key Awareness
*Impact: High — eliminates unnecessary proxy friction for browser-safe keys*

### Problem
`phantom init` protects `NEXT_PUBLIC_SUPABASE_ANON_KEY` and `EXPO_PUBLIC_POSTHOG_KEY` the same way it protects `SUPABASE_SERVICE_ROLE_KEY`. But public keys are designed to ship in browser bundles — they're not secrets. Wrapping them in phantom tokens means `npm run dev` won't work without `phantom exec`, even though the "secrets" are public.

### Implementation

**File: `crates/phantom-core/src/dotenv.rs`** — Modify `looks_like_secret()`

Add a `is_public_key()` check that detects framework-specific public prefixes:

```rust
fn is_public_key(key: &str) -> bool {
    let public_prefixes = [
        "NEXT_PUBLIC_",
        "EXPO_PUBLIC_",
        "VITE_",
        "REACT_APP_",
        "NUXT_PUBLIC_",
        "GATSBY_",
    ];
    public_prefixes.iter().any(|prefix| key.starts_with(prefix))
}
```

Modify `looks_like_secret()` to return a `SecretClassification` enum instead of `bool`:

```rust
pub enum SecretClassification {
    Secret,        // Protect with phantom token
    PublicKey,     // Framework public key — skip by default
    NotSecret,     // Environment config (NODE_ENV, PORT, etc.)
}
```

**File: `crates/phantom-cli/src/commands/init.rs`** — Update init flow

After detecting secrets, partition into secret vs public. Display public keys separately:

```
-> Found 3 secret(s) to protect:
   + SUPABASE_SERVICE_ROLE_KEY
   + STRIPE_SECRET_KEY
   + DATABASE_URL

-> Skipping 2 public key(s) (safe for browser bundles):
   · NEXT_PUBLIC_SUPABASE_ANON_KEY
   · NEXT_PUBLIC_SUPABASE_URL

   Override with: phantom add --force NEXT_PUBLIC_SUPABASE_ANON_KEY
```

**File: `crates/phantom-core/src/config.rs`** — Add `public_keys` field to PhantomConfig

```toml
[phantom]
public_keys = ["NEXT_PUBLIC_SUPABASE_ANON_KEY", "NEXT_PUBLIC_SUPABASE_URL"]
```

These are stored in `.phantom.toml` so the user's choice persists across `phantom rotate` and future inits.

**File: `crates/phantom-cli/src/commands/exec.rs`** — Already handles NEXT_PUBLIC_* passthrough

The exec command already has framework detection that passes through `NEXT_PUBLIC_*` vars. Verify this works correctly when those keys are NOT phantom-protected. No changes should be needed here, but validate with tests.

### Tests
- Unit test: `is_public_key()` correctly identifies all framework prefixes
- Unit test: `looks_like_secret()` returns `PublicKey` for `NEXT_PUBLIC_*` keys
- Integration test: `phantom init` on a Next.js `.env.local` skips public keys by default
- Integration test: `phantom add --force NEXT_PUBLIC_*` overrides the skip

### Verification
```bash
# Create a test .env with mixed keys
echo 'NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
SUPABASE_SERVICE_ROLE_KEY=eyJ...' > /tmp/test-env/.env

# Run phantom init — should only protect SERVICE_ROLE_KEY
cd /tmp/test-env && phantom init

# Verify: .env should have phm_ only for SERVICE_ROLE_KEY
cat .env
```

---

## Phase 2: Auto-Generate `.env.example` on Init
*Impact: High — solves team onboarding for every project*

### Problem
`phantom init` protects secrets but doesn't create `.env.example`. New developers cloning the repo have no template showing which env vars are needed. The `phantom env` command exists but isn't called during init.

### Implementation

**File: `crates/phantom-cli/src/commands/init.rs`** — Add `.env.example` generation after secret storage

After rewriting `.env` with phantom tokens, generate `.env.example` with key names and placeholder values:

```
-> Generated .env.example (commit this for team onboarding)
```

The generated `.env.example` should contain:
- All key names from the original `.env`
- Placeholder values showing the expected format:
  - `SUPABASE_SERVICE_ROLE_KEY=your-service-role-key`
  - `DATABASE_URL=postgres://user:password@host:5432/dbname`
  - `STRIPE_SECRET_KEY=sk_test_...`
  - Public keys: actual values (they're not secret)
- A header comment explaining Phantom:

```bash
# Environment variables for this project
# Copy to .env and fill in real values, or use Phantom:
#   npm install -g phantom-secrets && phantom init
#
# See https://phm.dev for details
```

**File: `crates/phantom-cli/src/commands/env.rs`** — Refactor to share logic

Extract the `.env.example` generation logic into a shared function in `phantom-core` that both `init.rs` and `env.rs` can call. Currently `env.rs` has its own implementation — unify them.

**File: `crates/phantom-core/src/dotenv.rs`** — Add `generate_example()` method

```rust
impl DotenvFile {
    pub fn generate_example(&self, classifications: &HashMap<String, SecretClassification>) -> String {
        // For each entry:
        //   Secret → key=placeholder_for_type (infer from key name)
        //   PublicKey → key=actual_value (safe to show)
        //   NotSecret → key=actual_value
        // Preserve comments and blank lines
    }
}
```

### Behavior
- If `.env.example` already exists, prompt: "Overwrite existing .env.example? [y/N]"
- Auto-run `git add .env.example` if in a git repo (with confirmation)
- Skip if `--no-example` flag is passed

### Tests
- Unit test: `generate_example()` produces correct placeholders for each secret type
- Unit test: Public keys retain their actual values in the example
- Integration test: `phantom init` creates `.env.example` alongside protected `.env`
- Integration test: Existing `.env.example` triggers overwrite prompt

---

## Phase 3: README Onboarding on Init
*Impact: High — humans (not just AI) understand the project uses Phantom*

### Problem
`phantom init` adds instructions to `CLAUDE.md` (AI-facing) but nothing to `README.md` (human-facing). A new developer sees `phm_` tokens with zero explanation.

### Implementation

**File: `crates/phantom-cli/src/commands/init.rs`** — Add README.md update step

After the CLAUDE.md update, offer to add a "Secrets" section to README.md:

```
ok Added Phantom instructions to CLAUDE.md
?  Add development setup section to README.md? [Y/n]
ok Added "Secrets" section to README.md
```

**Section to inject** (append before the last section, or at end):

```markdown
## Secrets

This project uses [Phantom](https://phm.dev) to protect API keys from AI agent leaks.

**Setup (with Phantom):**
```bash
npm i -g phantom-secrets  # or: npx phantom-secrets
phantom cloud pull         # restore team vault
phantom exec -- npm run dev
```

**Setup (manual):**
```bash
cp .env.example .env
# Fill in real API keys
npm run dev
```
```

**Detection logic**: Look for `## Secrets`, `## Environment`, or `## Setup` sections. If found, skip (don't duplicate). If not found, append the section.

**File: `crates/phantom-core/src/dotenv.rs` or new `crates/phantom-core/src/readme.rs`** — README manipulation utility

```rust
pub fn inject_readme_section(readme_content: &str, section: &str) -> Option<String> {
    // Returns None if section already exists
    // Returns Some(new_content) with section injected before last ## heading or at end
}
```

### Tests
- Unit test: Section injected at correct position in README
- Unit test: Duplicate injection prevented
- Unit test: Works with empty README, README without headings, README with existing Secrets section
- Integration test: `phantom init` updates README.md when user confirms

---

## Phase 4: Pre-Commit Hook Auto-Install
*Impact: Medium — prevents accidental secret commits*

### Problem
`phantom check` exists as a pre-commit scanner, and `phantom doctor` warns "No pre-commit hook", but `phantom init` doesn't install one. Users must manually wire it up.

### Implementation

**File: `crates/phantom-cli/src/commands/init.rs`** — Add hook installation step

After `.env` rewriting, offer to install the pre-commit hook:

```
?  Install pre-commit hook to scan for leaked secrets? [Y/n]
ok Installed .git/hooks/pre-commit
```

**Hook content** (`.git/hooks/pre-commit`):

```bash
#!/bin/sh
# Phantom Secrets pre-commit hook
# Scans staged files for unprotected secrets

npx phantom-secrets check --staged
exit $?
```

**Detection logic**:
1. Check if `.git/` directory exists (skip if not a git repo)
2. Check if `.git/hooks/pre-commit` already exists
   - If exists and contains "phantom", skip (already installed)
   - If exists and doesn't contain "phantom", ask to append
   - If doesn't exist, create it
3. `chmod +x` the hook file

**File: `crates/phantom-cli/src/commands/check.rs`** — Add `--staged` flag

Currently `phantom check` scans all files. Add `--staged` flag that only scans files in `git diff --cached --name-only`. This is faster and more appropriate for pre-commit hooks.

```rust
if args.staged {
    // Get staged files from git
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .output()?;
    let staged_files: Vec<&str> = ...;
    // Only scan staged files for unprotected secrets
}
```

### Tests
- Integration test: Hook installed in git repo
- Integration test: Hook skipped when no .git directory
- Integration test: Hook not duplicated on re-init
- Unit test: `phantom check --staged` only scans staged files

---

## Phase 5: `phantom wrap` / `phantom unwrap`
*Impact: High — eliminates the `phantom exec` prefix entirely*

### Problem
Developers must remember to type `phantom exec -- npm run dev` instead of `npm run dev`. IDE run buttons, VS Code launch configs, and muscle memory all break. This is the #1 daily friction point.

### Implementation

**File: `crates/phantom-cli/src/commands/wrap.rs`** — New command

`phantom wrap` rewrites `package.json` scripts to auto-prefix with phantom:

**Before:**
```json
{
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start"
  }
}
```

**After:**
```json
{
  "scripts": {
    "dev": "npx phantom-secrets exec -- next dev",
    "build": "npx phantom-secrets exec -- next build",
    "start": "npx phantom-secrets exec -- next start",
    "dev:raw": "next dev",
    "build:raw": "next build",
    "start:raw": "next start"
  }
}
```

**Behavior:**
- Saves original scripts as `*:raw` variants (escape hatch)
- Only wraps scripts that would benefit (skip `lint`, `test`, `format` — they don't need secrets)
- Detects scripts that already contain `phantom` and skips them
- `phantom unwrap` reverses the process (restores from `:raw` variants, removes `:raw` entries)

**Heuristic for which scripts to wrap** — wrap if the script:
- Contains `dev`, `start`, `serve`, `build`, `deploy` in the name
- Does NOT contain `lint`, `test`, `format`, `check`, `type` in the name
- Is not already wrapped

**File: `crates/phantom-cli/src/commands/unwrap.rs`** — Reverse command

Restores original scripts from `:raw` variants and removes `:raw` entries.

**File: `crates/phantom-cli/src/main.rs`** — Add Wrap/Unwrap to CLI

```rust
Wrap {
    /// Only wrap specific scripts
    #[arg(long)]
    only: Option<Vec<String>>,
    /// Skip specific scripts
    #[arg(long)]
    skip: Option<Vec<String>>,
},
Unwrap,
```

### Tests
- Unit test: Correct scripts identified for wrapping
- Unit test: Already-wrapped scripts skipped
- Unit test: `:raw` variants created correctly
- Unit test: `unwrap` restores original state exactly
- Integration test: `npm run dev` works after wrap (requires phantom vault)
- Integration test: `npm run dev:raw` works without phantom

### Edge Cases
- `package.json` doesn't exist (error with helpful message)
- Script uses `&&` chains or `concurrently` (wrap the entire value, not individual commands)
- Yarn/pnpm workspaces (handle `workspace:*` scripts)

---

## Phase 6: Cross-Project Secret Sharing
*Impact: Medium — critical for multi-repo teams sharing infrastructure*

### Problem
Two repos sharing a Supabase project need the same anon key, but Phantom manages secrets per-project. The workaround is a hacky `phantom exec -- sh -c 'cd ../other && phantom add ...'` command.

### Implementation

**File: `crates/phantom-cli/src/commands/copy.rs`** — New command

```bash
phantom copy EXPO_PUBLIC_SUPABASE_ANON_KEY --to ../slab-web --as NEXT_PUBLIC_SUPABASE_ANON_KEY
```

**Behavior:**
1. Load source project's vault
2. Retrieve the secret value
3. Load target project's `.phantom.toml` (must exist — target must be initialized)
4. Store the value in target project's vault under the new name
5. Update target project's `.env` file with a new phantom token
6. Zeroize the secret value from memory

**Arguments:**
```rust
Copy {
    /// Secret name in source project
    name: String,
    /// Target project directory
    #[arg(long)]
    to: PathBuf,
    /// Name in target project (defaults to same name)
    #[arg(long, alias = "as")]
    rename: Option<String>,
}
```

**Safety:**
- Requires both projects to be phantom-initialized
- Shows confirmation: "Copy EXPO_PUBLIC_SUPABASE_ANON_KEY → NEXT_PUBLIC_SUPABASE_ANON_KEY in ../slab-web? [y/N]"
- Never prints the secret value
- Zeroizes memory after copy

### Tests
- Integration test: Copy secret between two initialized projects
- Integration test: Copy with rename
- Integration test: Error when target not initialized
- Unit test: Vault value correctly transferred

---

## Phase 7: Enhanced `phantom doctor`
*Impact: Medium — better guidance when things aren't configured*

### Problem
`phantom doctor` warns about issues but doesn't tell the user how to fix them. "No pre-commit hook" is useless without "Run `phantom init` to install one" or the actual fix command.

### Implementation

**File: `crates/phantom-cli/src/commands/doctor.rs`** — Add actionable fix suggestions

For each check, provide:
1. Status (pass/warn/fail)
2. What's wrong (current)
3. **How to fix it** (new)
4. **Auto-fix option** (new, where safe)

```
Phantom Doctor

  ✓ Config file (.phantom.toml) found
  ✓ Vault backend: os-keychain (2 secrets)
  ✓ .env has phantom tokens (no real secrets detected)

  ⚠ No pre-commit hook installed
    Fix: phantom init (will offer to install hook)
    Or:  echo 'npx phantom-secrets check --staged' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

  ⚠ No sync targets configured
    Fix: Add to .phantom.toml:
    [[sync]]
    platform = "vercel"
    project_id = "your-vercel-project-id"

  ⚠ No .env.example found (team onboarding may be difficult)
    Fix: phantom env

  ⚠ README.md doesn't mention Phantom
    Fix: phantom init --update-readme

  ✓ Claude Code MCP configured

Run phantom doctor --fix to auto-fix all warnings.
```

**`--fix` flag**: Auto-apply safe fixes (install hook, generate .env.example, update README). Skip fixes that need user input (sync targets need project IDs).

### Tests
- Integration test: `phantom doctor` shows correct warnings
- Integration test: `phantom doctor --fix` resolves fixable warnings
- Unit test: Each check function returns correct status

---

## Phase 8: CI/CD Detection & Sync Setup
*Impact: Medium — bridges local dev to production*

### Problem
`phantom doctor` warns "No sync targets" but gives no guidance. Projects with `vercel.json`, `eas.json`, or `.github/workflows/` need platform-specific setup. Users don't know how to configure sync.

### Implementation

**File: `crates/phantom-cli/src/commands/init.rs`** — Add platform detection step

After secret protection, detect deployment platforms:

```
-> Detected deployment platforms:
   · Vercel (vercel.json found)
   · EAS Build (eas.json found)
   · GitHub Actions (.github/workflows/ found)

?  Configure secret sync for Vercel? [y/N]
   Enter Vercel project ID (from vercel.com/project/settings): ___
ok Added Vercel sync target to .phantom.toml
```

**Platform detection heuristic:**

| File | Platform | Sync Type |
|------|----------|-----------|
| `vercel.json` or `.vercel/` | Vercel | `phantom sync --platform vercel` |
| `eas.json` | EAS Build | Documentation only (EAS uses `eas secret:push`) |
| `.github/workflows/*.yml` | GitHub Actions | Documentation (use `PHANTOM_CLOUD_TOKEN`) |
| `fly.toml` | Fly.io | `phantom sync --platform fly` |
| `railway.json` or `railway.toml` | Railway | `phantom sync --platform railway` |
| `Dockerfile` | Docker | Documentation (use `PHANTOM_VAULT_PASSPHRASE`) |
| `netlify.toml` | Netlify | `phantom sync --platform netlify` |

**File: `crates/phantom-core/src/config.rs`** — Add sync target to config

```toml
[[sync]]
platform = "vercel"
project_id = "prj_xxxxx"
```

**File: `docs/ci-cd.md`** — New documentation

Create a comprehensive CI/CD guide with examples for each platform:

```markdown
## GitHub Actions
```yaml
- name: Pull secrets
  env:
    PHANTOM_CLOUD_TOKEN: ${{ secrets.PHANTOM_CLOUD_TOKEN }}
  run: npx phantom-secrets cloud pull
```

## Vercel
```bash
phantom sync --platform vercel
```

## EAS Build
```bash
# EAS doesn't support custom CLIs in build
# Use eas secret:push or set env vars in eas.json
phantom export --format eas | eas secret:push --force
```
```

### Tests
- Unit test: Platform detection correctly identifies each platform
- Integration test: Sync target added to `.phantom.toml` for detected platform

---

## Phase 9: Small DX Wins
*Impact: Low-Medium each, high cumulatively*

### 9a. `phantom why <KEY>`

**File: `crates/phantom-cli/src/commands/why.rs`** — New command

Explains why a specific key is or isn't protected:

```bash
$ phantom why NEXT_PUBLIC_SUPABASE_ANON_KEY
NEXT_PUBLIC_SUPABASE_ANON_KEY is NOT protected (public key)
  Reason: Keys with NEXT_PUBLIC_ prefix are browser-safe (shipped in client bundles)
  Override: phantom add --force NEXT_PUBLIC_SUPABASE_ANON_KEY

$ phantom why SUPABASE_SERVICE_ROLE_KEY
SUPABASE_SERVICE_ROLE_KEY is PROTECTED
  Token: phm_dcd98d94...
  Service: supabase (api.supabase.co)
  Vault: os-keychain
  Last rotated: 2026-04-04
```

### 9b. Better proxy-not-running errors

**File: `crates/phantom-proxy/src/interceptor.rs`** — Not applicable here (proxy is local)

This is actually a client-side SDK issue. When Supabase/OpenAI SDKs receive a `phm_` token, they send it to the real API and get a 401. The user sees a cryptic auth error.

**Better approach: `phantom check --runtime`** — New flag

Scans the current environment for `phm_` tokens in API key env vars and warns:

```bash
$ phantom check --runtime
⚠ SUPABASE_SERVICE_ROLE_KEY contains phantom token (phm_dcd98d94...)
  The proxy is not running. Start it with: phantom exec -- <your-command>
```

This could be added to `package.json` as a `predev` script by `phantom wrap`:

```json
{
  "scripts": {
    "predev": "npx phantom-secrets check --runtime 2>/dev/null || true",
    "dev": "next dev"
  }
}
```

### 9c. Shell prompt integration

**File: `docs/shell-prompt.md`** — New documentation

```bash
# Starship (starship.toml)
[custom.phantom]
command = "phantom status --oneline 2>/dev/null"
when = "test -f .phantom.toml"
format = "[$output]($style) "
style = "dimmed white"

# Zsh (add to .zshrc)
phantom_status() {
  if [ -f .phantom.toml ]; then
    local status=$(phantom status --oneline 2>/dev/null)
    [ -n "$status" ] && echo " [phm:$status]"
  fi
}
PROMPT='%~ $(phantom_status)%# '
```

**File: `crates/phantom-cli/src/commands/status.rs`** — Add `--oneline` flag

```
$ phantom status --oneline
2 secrets · proxy off
```

Or when proxy is running:
```
$ phantom status --oneline
2 secrets · proxy :52630
```

### 9d. MCP tool: `phantom_copy_secret`

**File: `crates/phantom-mcp/src/server.rs`** — Add new tool

```rust
phantom_copy_secret {
    name: String,
    target_dir: String,
    rename: Option<String>,
}
```

This enables AI agents to copy secrets between projects via MCP without ever seeing the value — extends the Phase 6 `phantom copy` functionality to MCP.

---

## Implementation Sequence

```
Phase 1: Public Key Awareness        [2-3 hours]  ← Start here, biggest bang for buck
Phase 2: Auto-Generate .env.example  [1-2 hours]  ← Quick win, high impact
Phase 3: README Onboarding           [1-2 hours]  ← Quick win, high impact
Phase 4: Pre-Commit Hook             [1-2 hours]  ← Quick win, prevents real damage
Phase 5: phantom wrap/unwrap         [3-4 hours]  ← Biggest DX improvement
Phase 6: Cross-Project Copy          [2-3 hours]  ← Important for multi-repo
Phase 7: Enhanced Doctor             [2-3 hours]  ← Polish
Phase 8: CI/CD Detection             [2-3 hours]  ← Bridges to production
Phase 9: Small DX Wins               [3-4 hours]  ← Cumulative polish
```

**Dependency order**: Phases 1-4 are independent (can parallelize). Phase 5 depends on nothing. Phase 6 is independent. Phase 7 benefits from Phases 2-4 (more things to check). Phase 8 is independent. Phase 9 is independent.

**Recommended batches for parallel work:**
- **Batch A**: Phases 1 + 2 + 3 (all modify init.rs, touch dotenv.rs)
- **Batch B**: Phases 4 + 5 (new commands, independent)
- **Batch C**: Phases 6 + 7 + 8 (new commands, config changes)
- **Batch D**: Phase 9 (polish, after core features land)

---

## Critical Files Reference

| File | Phases | Purpose |
|------|--------|---------|
| `crates/phantom-core/src/dotenv.rs` | 1, 2 | Secret detection + .env.example generation |
| `crates/phantom-core/src/config.rs` | 1, 8 | Config schema (public_keys, sync targets) |
| `crates/phantom-cli/src/commands/init.rs` | 1, 2, 3, 4, 8 | Init flow orchestration |
| `crates/phantom-cli/src/commands/check.rs` | 4, 9b | Pre-commit scanning |
| `crates/phantom-cli/src/commands/doctor.rs` | 7 | Health checks with fix suggestions |
| `crates/phantom-cli/src/commands/status.rs` | 9c | Oneline status for shell prompt |
| `crates/phantom-cli/src/commands/wrap.rs` | 5 | New: package.json script wrapping |
| `crates/phantom-cli/src/commands/unwrap.rs` | 5 | New: reverse wrap |
| `crates/phantom-cli/src/commands/copy.rs` | 6 | New: cross-project secret copy |
| `crates/phantom-cli/src/commands/why.rs` | 9a | New: explain key classification |
| `crates/phantom-cli/src/commands/env.rs` | 2 | Refactor to share with init |
| `crates/phantom-cli/src/main.rs` | 5, 6, 9a | Add new subcommands to clap |
| `crates/phantom-mcp/src/server.rs` | 9d | Add copy tool to MCP |
| `docs/ci-cd.md` | 8 | New: CI/CD integration guide |
| `docs/shell-prompt.md` | 9c | New: shell prompt integration |

---

## Testing Strategy

All new features should follow the existing pattern:
- Unit tests inline with `#[cfg(test)] mod tests` in each source file
- Integration tests in `tests/` directory for cross-crate behavior
- Run full suite: `cargo test --workspace`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt --all -- --check`

**New test fixtures needed:**
- `.env` files with mixed public/secret keys (Phase 1)
- `package.json` files with various script patterns (Phase 5)
- Multi-project directory layouts (Phase 6)
- Project dirs with various platform configs (Phase 8)

---

## Verification Checklist

After implementing all phases, verify end-to-end:

1. **Fresh project**: `phantom init` on a new Next.js + Supabase project should:
   - Protect only secret keys (not `NEXT_PUBLIC_*`)
   - Generate `.env.example`
   - Offer to update README.md
   - Offer to install pre-commit hook
   - Detect Vercel/EAS and suggest sync config

2. **Daily dev**: `npm run dev` should work after `phantom wrap` without `phantom exec` prefix

3. **Multi-repo**: `phantom copy KEY --to ../other-repo --as OTHER_KEY` should transfer secrets without exposing values

4. **Team onboarding**: A new developer should be able to:
   - Clone repo
   - Read README.md "Secrets" section
   - Run `phantom cloud pull`
   - Run `npm run dev`
   - Total time: under 2 minutes

5. **CI/CD**: GitHub Actions should be able to:
   - Pull secrets via `PHANTOM_CLOUD_TOKEN`
   - Build and deploy without manual secret management

6. **Pre-commit**: Committing an unprotected `.env` should be blocked by the hook

7. **Doctor**: `phantom doctor` should report all issues with actionable fix commands
