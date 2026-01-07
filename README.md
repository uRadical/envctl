# envctl

Zero-infrastructure secrets sharing for dev teams — encrypted, peer-to-peer, no cloud.

**[envctl.dev](https://envctl.dev)** · [Documentation](#usage) · [Install](#installation)

## Features

- **Post-quantum encryption** — ML-KEM-768 for future-proof security
- **Peer-to-peer** — No server, no cloud, your secrets stay local
- **Cryptographic team membership** — Blockchain-based team verification
- **Variable-level redaction** — Choose exactly what to share
- **Works everywhere** — LAN, VPN, or Tailscale
- **Cross-platform** — Linux, macOS, Windows

## Quick Start

```bash
# Install
go install envctl.dev/go/envctl@latest

# Initialize your identity
envctl identity init

# Start the daemon
envctl daemon start

# Create a project
envctl project create myproject

# Set environment variables
envctl env var set DATABASE_URL=postgres://localhost/myapp
```

## Installation

### From Source

Requires Go 1.23 or later:

```bash
git clone https://github.com/uradical/envctl
cd envctl
make install
```

### Binary Releases

Download from the [releases page](https://github.com/uradical/envctl/releases).

## Setup

### 1. Initialize Identity

Each device has its own identity with unique cryptographic keys:

```bash
envctl identity init
# Enter a passphrase to protect your identity
```

For hardware-backed security, use a YubiKey:

```bash
envctl identity init --yubikey
```

This creates your identity files in `~/.config/envctl/`.

### 2. Start the Daemon

The daemon handles peer-to-peer connections:

```bash
envctl daemon start
```

To install as a user service (auto-start on login):

```bash
envctl daemon install
```

### 3. Create or Join a Project

Create a new project:

```bash
envctl project create myproject
```

Or join an existing project using an invite code:

```bash
envctl project join ABC-DEF-GHI
```

## Usage

### Project Setup

Link a directory to an existing project:

```bash
cd ~/projects/myapp
envctl project link myproject
```

This creates a `.envctl/` directory in your project.

### Setting Environment Variables

```bash
# Set variables for the current environment
envctl env var set DATABASE_URL=postgres://localhost/myapp
envctl env var set API_KEY=dev-key-12345

# List current variables
envctl env var list
```

### Syncing with Team

Environment variables sync automatically with connected peers. Check sync status:

```bash
envctl status
```

### Managing Environments

List environment files:

```bash
envctl env list
```

Switch environments (creates symlink):

```bash
envctl env use prod
```

### Variable History

View who changed what and when:

```bash
envctl env var log
envctl env var log --key API_KEY
```

## Shell Integration

Add environment status to your shell prompt.

### Starship

```toml
# ~/.config/starship.toml
[custom.envctl]
command = "envctl prompt"
when = "test -f .envctl"
format = "[$output]($style)"
style = "none"
```

### Oh-My-Zsh

```bash
# ~/.oh-my-zsh/custom/plugins/envctl/envctl.plugin.zsh
envctl_prompt() {
    if [[ -f .envctl ]]; then
        envctl prompt 2>/dev/null
    fi
}
PROMPT='$(envctl_prompt) '$PROMPT
```

### Pure

```bash
# ~/.zshrc
prompt_envctl() {
    if [[ -f .envctl ]]; then
        preprompt+=" $(envctl prompt 2>/dev/null)"
    fi
}
prompt_pure_precmd_functions+=(prompt_envctl)
```

## Passphrase Management

To avoid entering your passphrase every time the daemon starts, use the `--keychain` flag during initialization:

```bash
envctl identity init --keychain
```

This stores your passphrase in the system keychain (macOS Keychain, Windows Credential Manager, or libsecret on Linux). The daemon will automatically retrieve it on startup.

If you didn't use `--keychain` during init, you'll be prompted for your passphrase each time you start the daemon.

## Identity Management

### Backup and Recovery

Export your identity as a mnemonic phrase for paper backup:

```bash
envctl identity export
# Displays 24 words - write them down and store securely
```

Recover from backup on a new device:

```bash
envctl identity recover
# Enter your 24 words to restore
```

### Key Rotation

Rotate your identity keys periodically or if you suspect compromise:

```bash
envctl identity rotate-key
```

This will:
1. Generate a new Ed25519 + ML-KEM key pair
2. Re-encrypt all your local secrets with the new key
3. Announce your new public key to team members
4. Back up your old key (securely deleted after 7 days)

Options:
- `--same-passphrase` — Keep the current passphrase
- `--local-only` — Skip team announcement
- `--search-dirs` — Directories to search for secrets

### List Keys

View your configured identity keys:

```bash
envctl identity keys
```

### Device Linking

Transfer your identity to a new device securely using a short pairing code:

On your existing device:
```bash
envctl identity link
# Displays a 6-digit code like: 847 392
```

On your new device:
```bash
envctl identity link --code 847392
# Verify the fingerprint matches, then enter your passphrase
```

The devices connect directly via your local network (mDNS discovery) and use SPAKE2 password-authenticated key exchange. The code is valid for 5 minutes.

## Project Management

### Invite Members

```bash
envctl project invite alice --pubkey <pubkey> --env dev,stage
```

### Manage Access

```bash
# View who has access to what
envctl project access

# Grant prod access
envctl project grant alice --env prod

# Revoke access
envctl project revoke alice --env prod
```

### View Chain History

```bash
envctl project log
```

## Security Model

### Cryptography

- **ML-KEM-768** — Post-quantum key encapsulation (NIST standard)
- **AES-256-GCM** — Symmetric encryption
- **Ed25519** — Digital signatures
- **Argon2id** — Password-based key derivation
- **HKDF** — Key derivation

### Trust Model

1. **Identity** — Each device has unique cryptographic keys
2. **Team Membership** — Blockchain-based, requires approval
3. **Environment Access** — Per-environment permissions
4. **Peer Verification** — Optional SAS verification for MITM detection

### Data Storage

All data is stored locally:

- `~/.config/envctl/identity.enc` — Encrypted private keys
- `~/.config/envctl/identity.pub` — Public identity (shareable)
- `~/.config/envctl/chains/` — Team membership chains
- `~/.config/envctl/audit.log` — Local sharing history
- `~/.config/envctl/envctl.sock` — Daemon IPC socket

No data is sent to any cloud service.

## Configuration

Create `~/.config/envctl/config.toml`:

```toml
[identity]
name = "alice"

[daemon]
p2p_port = 7834
web_port = 7835
web_enabled = true

[discovery]
mdns = true
manual_peers = [
    "bob-laptop.local:7834",
    "192.168.1.50:7834"
]

[logging]
level = "info"

[defaults]
project = "myproject"
```

## Commands

```
envctl
├── identity
│   ├── init                # Initialize identity
│   ├── export              # Export as mnemonic
│   ├── recover             # Recover from mnemonic
│   ├── rotate-key          # Rotate identity keys
│   ├── link                # Link to another device
│   ├── migrate             # Migrate to YubiKey
│   ├── keys                # List configured keys
│   └── pubkey              # Show public key
├── daemon
│   ├── run                 # Run in foreground
│   ├── start               # Start background
│   ├── stop                # Stop daemon
│   ├── status              # Show status
│   ├── env                 # Print shell env vars
│   ├── install             # Install as service
│   └── uninstall           # Remove service
├── project (alias: team)
│   ├── create <name>       # Create project
│   ├── join <code>         # Join with invite code
│   ├── list                # List projects
│   ├── members             # List members
│   ├── invite              # Invite member
│   ├── remove              # Remove member
│   ├── leave               # Leave project
│   ├── access              # Show access
│   ├── grant               # Grant access
│   ├── revoke              # Revoke access
│   ├── log                 # Chain history
│   ├── link                # Link directory to project
│   └── env                 # Manage environments
├── env
│   ├── list                # List environments
│   ├── use <name>          # Switch environment
│   ├── current             # Show current
│   └── var
│       ├── list            # List variables
│       ├── get <key>       # Get variable
│       ├── set <key=val>   # Set variable
│       ├── delete <key>    # Delete variable
│       └── log             # Variable history
├── peers
│   ├── list                # Connected peers
│   ├── add <addr>          # Add peer manually
│   └── saved               # Show saved peers
├── verify <peer>           # SAS verification
├── status                  # Show current status
├── whoami                  # Show identity
├── doctor                  # Health checks
├── log                     # View logs
├── ui                      # Open web UI
├── prompt                  # Shell prompt output
└── version                 # Show version
```

## Building from Source

Requirements:
- Go 1.23 or later

```bash
git clone https://github.com/uradical/envctl
cd envctl
make build
```

Run tests:

```bash
make test
```

Build for all platforms:

```bash
make build-all
```

## Contributing

Contributions welcome! Please read the contributing guidelines first.

## License

MIT — see [LICENSE](LICENSE)
