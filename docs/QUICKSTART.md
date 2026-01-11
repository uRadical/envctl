# Getting Started with envctl

This guide walks you through setting up envctl and sharing your first environment variables with a team.

## Installation

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/uradical/envctl/main/install.sh | sh
```

Or manually:

```bash
# Determine your OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
VERSION=$(curl -s https://api.github.com/repos/uradical/envctl/releases/latest | grep tag_name | cut -d '"' -f 4)

# Download and install
curl -LO "https://github.com/uradical/envctl/releases/download/${VERSION}/envctl_${VERSION#v}_${OS}_${ARCH}.tar.gz"
tar xzf envctl_${VERSION#v}_${OS}_${ARCH}.tar.gz
sudo mv envctl /usr/local/bin/
```

### Windows

Download from the [releases page](https://github.com/uradical/envctl/releases/latest) and add to your PATH.

### From Source

Requires Go 1.23 or later:

```bash
git clone https://github.com/uradical/envctl
cd envctl
make install
```

### Verify Installation

```bash
envctl version
```

## Initial Setup

### 1. Create Your Identity

Your identity is your cryptographic keypair used for signing and encryption:

```bash
envctl identity init
```

You'll be prompted for:
- **Identity name**: A display name (default: username-hostname)
- **Passphrase**: Protects your private key at rest

**With keychain integration** (recommended for convenience):

```bash
envctl identity init --keychain
```

This stores your passphrase in the system keychain so the daemon can start without prompting.

### 2. Start the Daemon

The daemon handles P2P connections and synchronization:

```bash
envctl daemon start
```

Check status:

```bash
envctl daemon status
```

### 3. View Your Identity

```bash
envctl whoami
```

This shows your identity name, fingerprint, and public key.

## Creating a Project

### 1. Initialize a Project

Navigate to your project directory:

```bash
cd ~/projects/myapp
envctl project create myapp
```

This creates:
- A team chain for membership management
- Default environments (dev, stage, prod)
- A `.envctl/` directory in your project

### 2. Set Environment Variables

```bash
# Set variables for the dev environment
envctl env var set DATABASE_URL=postgres://localhost/myapp_dev
envctl env var set API_KEY=dev-key-12345

# View current variables
envctl env var list
```

### 3. Use Variables in Your Shell

Unlock variables to `.env`:

```bash
envctl env unlock
```

Or export directly:

```bash
eval $(envctl env export)
```

## Inviting Team Members

### 1. Get Their Public Key

Have your team member run:

```bash
envctl whoami --pubkey
```

They'll share something like:

```
ed25519:a1b2c3d4e5f6...
```

### 2. Create an Invite

```bash
envctl project invite alice --pubkey ed25519:a1b2c3d4e5f6...
```

This outputs an invite code:

```
Invite created: ABC-DEF-GHI
Share this code with alice (expires in 10 minutes)
```

### 3. Team Member Joins

The invited person runs:

```bash
envctl project join ABC-DEF-GHI
```

They're now part of the team and can sync environment variables.

## Synchronizing with Peers

### Automatic Discovery

On the same network, peers discover each other via mDNS:

```bash
envctl peers list
```

### Manual Peer Connection

For peers on different networks:

```bash
envctl peers add 192.168.1.100:7834
```

### Sync Status

Check what's synchronized:

```bash
envctl status
```

## Switching Environments

### List Environments

```bash
envctl env list
```

### Switch Environment

```bash
envctl env use prod
```

### View Variables for an Environment

```bash
envctl env var list --env prod
```

## Common Workflows

### Daily Development

```bash
# Start daemon (if not using auto-start)
envctl daemon start

# Navigate to project
cd ~/projects/myapp

# Unlock environment variables
envctl env unlock

# Work on your project...
# Variables auto-sync with team members
```

### Adding a Secret

```bash
# Set a new variable
envctl env var set STRIPE_KEY=sk_live_xxx

# It syncs automatically to connected peers
```

### Checking History

```bash
# View who changed what
envctl env history

# Filter by variable
envctl env history --key API_KEY
```

### Rotating a Secret

```bash
# Update the value
envctl env var set API_KEY=new-key-value

# Old value is preserved in history
```

## Project Structure

After setup, your project looks like:

```
myapp/
├── .envctl/
│   ├── config           # Project configuration
│   ├── dev.enc          # Encrypted dev environment
│   ├── stage.enc        # Encrypted stage environment
│   └── prod.enc         # Encrypted prod environment
├── .env                  # Unlocked variables (gitignored)
├── .gitignore           # Should include .env
└── ...
```

## Shell Integration

### Bash/Zsh

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# Auto-start daemon
eval "$(envctl daemon env)"

# Optional: show current env in prompt
export PS1='$(envctl prompt)'"$PS1"
```

### Fish

Add to `~/.config/fish/config.fish`:

```fish
envctl daemon env | source
```

## Auto-Start Daemon

### macOS (launchd)

```bash
envctl daemon install
```

### Linux (systemd)

```bash
envctl daemon install
```

This creates a user service that starts the daemon on login.

## Troubleshooting

### Daemon Won't Start

```bash
# Check status
envctl daemon status

# View logs
envctl log --since 5m

# Try running in foreground
envctl daemon run
```

### Can't Connect to Peers

```bash
# Check if daemon is running
envctl daemon status

# List discovered peers
envctl peers list

# Check network connectivity
ping <peer-ip>
```

### Identity Issues

```bash
# View identity details
envctl whoami

# Verify identity file exists
ls -la ~/.config/envctl/identity.enc
```

### Reset Everything

```bash
# Stop daemon
envctl daemon stop

# Remove config (careful - this deletes your identity!)
rm -rf ~/.config/envctl
```

## Next Steps

- Read the [Architecture](ARCHITECTURE.md) document for system design
- Review [Security](SECURITY.md) for the threat model
- Check [Configuration](CONFIGURATION.md) for all options
- Explore [Storage](STORAGE.md) for how data is managed

## Quick Reference

| Command | Description |
|---------|-------------|
| `envctl identity init` | Create identity |
| `envctl daemon start` | Start background daemon |
| `envctl project create <name>` | Create new project |
| `envctl env var set KEY=value` | Set variable |
| `envctl env var list` | List variables |
| `envctl env unlock` | Write to .env file |
| `envctl env use <env>` | Switch environment |
| `envctl project invite <name>` | Invite team member |
| `envctl peers list` | Show connected peers |
| `envctl status` | Show current status |
| `envctl whoami` | Show identity |
