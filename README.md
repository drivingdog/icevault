[IceVault](https://i.postimg.cc/Dzd3KWDp/Gemini-Generated-Image-whz9bhwhz9bhwhz9-(1).png)

# IceVault

Local secret manager for developers. Store encrypted secrets in a vault and inject them as environment variables at runtime — secrets never touch disk in plaintext.

```
DATABASE_URL="iv://MyProject/Database/url"   ← safe to commit
API_KEY="iv://MyProject/Stripe/api_key"      ← references, not real values
```

```bash
icevault run --env-file=.env -- npm run dev  ← secrets injected only in memory
```

---

## How it works

1. Secrets are stored encrypted in `~/.icevault/vault.ice` (AES-equivalent: ChaCha20-Poly1305 + Argon2id key derivation)
2. Your `.env` file contains only `iv://Vault/Category/key` references — safe to commit to git
3. `icevault run` resolves references and injects real values as environment variables into your process
4. Secrets exist only in memory during execution and are never written to disk

---

## Installation

### Requirements

- [Rust](https://rustup.rs/) 1.70 or later

### Build from source

```bash
git clone <repo>
cd icevault
cargo install --path .
```

The binary is installed to `~/.cargo/bin/icevault` which is in your PATH if you installed Rust via rustup.

### Verify installation

```bash
icevault --version
```

---

## Quick start

### 1. Initialize the vault

```bash
icevault init
```

Creates `~/.icevault/vault.ice`. Run this once — the vault is global and shared across all your projects.

### 2. Add secrets

```bash
icevault add MyProject/Database/url
# Secret value:   ****    (hidden input)
# Confirm value:  ****
# Master password: ****
# Stored: MyProject/Database/url
```

The path format is `Vault/Category/key`:
- **Vault** — usually your project or organization name (`MyProject`, `Ecommerce`)
- **Category** — groups related secrets (`Database`, `Auth`, `Stripe`)
- **key** — the specific secret name (lowercase, e.g. `url`, `api_key`, `jwt_secret`)

### 3. Create a `.env` file with references

```bash
# .env — safe to commit to git
DATABASE_URL="iv://MyProject/Database/url"
JWT_SECRET="iv://MyProject/Auth/jwt_secret"
STRIPE_KEY="iv://MyProject/Stripe/api_key"

# Regular variables (no secret) stay as-is
PORT=3000
NODE_ENV=development
```

### 4. Run your project

```bash
icevault run --env-file=.env -- npm run dev
icevault run --env-file=.env -- cargo run
icevault run --env-file=.env -- python manage.py runserver
```

---

## Commands

### `icevault init`

Initialize a new encrypted vault. Only needed once.

```bash
icevault init

# Custom location
icevault --vault ./project.ice init
```

---

### `icevault add <Vault/Category/key>`

Add a secret interactively. Prompts for the value with hidden input — never stored in shell history or visible in process listings.

```bash
icevault add Ecommerce/Database/connection_string
icevault add Ecommerce/Telegram/chat_id
icevault add Ecommerce/Stripe/secret_key
```

---

### `icevault list [filter]`

List stored secret paths. Values are never shown.

```bash
icevault list              # all secrets
icevault list Ecommerce    # filter by vault name

# Output:
# Ecommerce/Database/connection_string
# Ecommerce/Stripe/secret_key
# Ecommerce/Telegram/chat_id
```

---

### `icevault delete <Vault/Category/key>`

Delete a secret from the vault.

```bash
icevault delete Ecommerce/Telegram/chat_id
```

---

### `icevault run --env-file=<path> -- <command>`

Resolve `iv://` references and inject secrets as environment variables into a child process.

```bash
icevault run --env-file=.env -- npm run dev
icevault run --env-file=.env -- npx prisma migrate dev
icevault run --env-file=.env.production -- cargo run --release
```

On Linux/macOS, uses `execve()` — the parent process is replaced and all memory (including secrets) is reclaimed by the OS.

On Windows, spawns a child process, zeroizes secrets in the parent immediately after spawn, then waits.

---

### `icevault migrate --env-file=<path> --prefix=<Vault/Category>`

Migrate an existing `.env` file with real values into the vault. Creates a new `.env.ice` file with `iv://` references.

```bash
icevault migrate --env-file=.env.local --prefix=Ecommerce/Development
```

Given `.env.local`:
```bash
# Database config
DATABASE_URL=postgres://user:pass@localhost/db
TELEGRAM_CHAT_ID=-546455445
PORT=3000
```

Produces `.env.local.ice`:
```bash
# Database config
DATABASE_URL="iv://Ecommerce/Development/database_url"
TELEGRAM_CHAT_ID="iv://Ecommerce/Development/telegram_chat_id"
PORT=3000
```

Rules:
- Comments and blank lines are preserved as-is
- Variables with real values → migrated to vault + replaced with `iv://` reference
- Empty values and existing `iv://` references → copied unchanged
- Variable names are lowercased for the vault key (`TELEGRAM_CHAT_ID` → `telegram_chat_id`)
- Asks for master password only once for the entire migration

---

### `icevault export --env-file=<path> --confirm`

Print resolved environment variables to stdout. For debugging only — prints real secret values.

```bash
icevault export --env-file=.env --confirm
```

The `--confirm` flag is required to prevent accidental use. Do not run this in CI logs.

---

## Skipping the password prompt

Set the `ICEVAULT_PASSWORD` environment variable to avoid being prompted on every run.

```bash
# Windows (current session)
set ICEVAULT_PASSWORD=your-master-password

# Windows (permanent for your user)
setx ICEVAULT_PASSWORD "your-master-password"

# Linux/macOS
export ICEVAULT_PASSWORD=your-master-password
```

IceVault reads the variable and immediately removes it from the environment so child processes never inherit the master password.

---

## Multiple vaults

Use `--vault` to specify a custom vault path. Useful for separating secrets between projects or environments.

```bash
icevault --vault ./ecommerce.ice init
icevault --vault ./ecommerce.ice add Ecommerce/Database/url
icevault --vault ./ecommerce.ice run --env-file=.env -- npm run dev
```

---

## Typical project setup

```bash
# Step 1 — initialize vault (once, global)
icevault init

# Step 2 — add your project's secrets
icevault add MyApp/Database/url
icevault add MyApp/Auth/jwt_secret
icevault add MyApp/Stripe/api_key

# Step 3 — create .env with references
cat > .env << 'EOF'
DATABASE_URL="iv://MyApp/Database/url"
JWT_SECRET="iv://MyApp/Auth/jwt_secret"
STRIPE_KEY="iv://MyApp/Stripe/api_key"
PORT=3000
EOF

# Step 4 — add .env to git (safe — no real secrets)
git add .env

# Step 5 — run your app
icevault run --env-file=.env -- npm run dev
```

Or migrate from an existing `.env` file in one step:

```bash
icevault migrate --env-file=.env --prefix=MyApp/Production
# → secrets stored in vault
# → .env.ice created with iv:// references
```

---

## Security

| Property | Implementation |
|----------|---------------|
| Encryption | ChaCha20-Poly1305 (authenticated encryption) |
| Key derivation | Argon2id — 128 MiB memory, 3 iterations |
| Salt | 32 bytes, random per write — no IV reuse |
| Memory | Secrets zeroized after use (`zeroize` crate) |
| Password comparison | Constant-time (`subtle` crate) |
| Vault writes | Atomic (tmp file + rename) |
| File permissions | `0600` on Unix (owner read/write only) |
| Child process | Master password removed from env before exec |
| `.env` file | Contains only references — safe to commit |

### What is stored on disk

| File | Contents | Real secrets? |
|------|----------|---------------|
| `~/.icevault/vault.ice` | Encrypted blob (ChaCha20-Poly1305) | No — unreadable without master password |
| `.env` in your project | `iv://` references only | No — safe to commit |
| `.env.ice` (after migrate) | `iv://` references only | No — safe to commit |

### What stays in memory only

- Decrypted secret values during `icevault run`
- The master password (zeroized immediately after key derivation)
- Derived encryption key (zeroized after encrypt/decrypt)

---

## .gitignore recommendations

```gitignore
# Real .env files with actual secrets — never commit these
.env.real
.env.local
.env.development
.env.production

# .env.ice files with iv:// references are safe to commit
# (no entry needed)
```
