# envctl Configuration Reference

This document covers all configuration options, environment variables, and command-line flags.

## Configuration Files

### Global Configuration

**Location:** `~/.config/envctl/config.toml`

Override with: `ENVCTL_CONFIG_DIR` environment variable

```toml
[identity]
name = "alice"                    # Display name for your identity

[daemon]
p2p_port = 7834                   # P2P network port
web_port = 7835                   # Web UI port
web_enabled = true                # Enable web UI

[discovery]
mdns = true                       # Enable mDNS peer discovery
manual_peers = [                  # Static peer addresses
    "192.168.1.100:7834",
    "peer.example.com:7834"
]

[logging]
level = "info"                    # debug, info, warn, error
format = "text"                   # text, json

[notifications]
enabled = true                    # Enable desktop notifications

[defaults]
team = "myproject"                # Default project/team name
```

### Project Configuration

**Location:** `.envctl/config` in project directory

```ini
project=myproject                 # Project/team name
env=dev                           # Current environment
locked=true                       # Whether .env is removed from disk
auto_lock_minutes=480             # Auto-lock timeout (0 = disabled)
last_unlocked=2024-12-30T12:00:00Z
```

## Environment Variables

### Path Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVCTL_CONFIG_DIR` | Platform-specific | Override entire config directory |
| `XDG_RUNTIME_DIR` | `/run/user/<uid>` | Linux runtime directory (socket path) |
| `APPDATA` | - | Windows application data directory |

### Behavior

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVCTL_LANG` | Auto-detect | Override language selection |
| `LC_MESSAGES` | - | Language (priority 2) |
| `LANG` | - | Language (priority 3) |
| `LC_ALL` | - | Language (priority 4) |
| `EDITOR` | - | Editor for interactive editing |
| `VISUAL` | - | Alternative editor |

## Directory Structure

### Global (~/.config/envctl/)

```
~/.config/envctl/
├── config.toml              # Main configuration
├── identity.enc             # Encrypted private key
├── identity.pub             # Public key (shareable)
├── identity.json            # Identity metadata
├── daemon.pid               # Daemon process ID
├── audit.log                # Audit log
├── peers.json               # Known peers
├── chains/                  # Team chains
│   └── <project>.chain
├── secrets/                 # Cached secrets
│   └── <project>/
│       └── <env>.enc
└── pending/                 # Pending operations
    ├── proposals/
    └── requests/
```

### Per-Project (.envctl/)

```
project/
├── .envctl/
│   ├── config               # Project config
│   ├── dev.enc              # Encrypted environments
│   ├── stage.enc
│   └── prod.enc
└── .env                     # Unlocked variables (gitignored)
```

### Platform-Specific Paths

| Path | Linux | macOS | Windows |
|------|-------|-------|---------|
| Config | `~/.config/envctl/` | `~/.config/envctl/` | `%APPDATA%\envctl\` |
| Socket | `$XDG_RUNTIME_DIR/envctl.sock` | `~/Library/Application Support/envctl/daemon.sock` | `\\.\pipe\envctl-<user>` |
| Temp | `/tmp/envctl-<uid>` | `/tmp/envctl-<uid>` | `%TEMP%\envctl` |

## Command-Line Reference

### Global Flags

Available on all commands:

```
--config <path>      Config file path
--lang <lang>        Override language
-v, --verbose        Enable verbose output
```

### daemon

**daemon run** - Run daemon in foreground

```
--p2p-port <int>     P2P port (default: 7834)
--web-port <int>     Web UI port (default: 7835)
--log-file <path>    Log file path
```

**daemon start** - Start daemon in background

**daemon stop** - Stop the daemon

**daemon status** - Show daemon status

**daemon env** - Print shell environment

**daemon install** - Install as user service

**daemon uninstall** - Remove user service

### identity

**identity init** - Initialize identity

```
--name <name>        Identity name (default: user-hostname)
--yubikey            Store on YubiKey
--keychain           Store passphrase in system keychain
```

### project / team

**project create [name]** - Create new project

```
--envs <list>        Environments (default: dev,stage,prod)
--default-access <env>  Default environment for new members
--auto-detect        Auto-detect from .env.* files (default: true)
--no-envctl          Don't create .envctl directory
```

**project list** - List projects

```
--json               Output as JSON
```

**project invite <name>** - Create invite

```
--pubkey <key>       Invitee's public key (required)
--ttl <duration>     Expiration (default: 10m)
--env <list>         Environments to grant
--role <role>        Role: admin, member, reader (default: member)
```

**project invites** - List invites

**project revoke-invite <code>** - Revoke invite

```
--reason <text>      Revocation reason
```

**project members** - Show members

**project access** - Show environment access

**project grant <member>** - Grant environment access

```
--env <list>         Environments to grant (required)
```

**project revoke <member>** - Revoke access

```
--env <list>         Environments to revoke (required)
```

**project remove <name>** - Remove member

**project leave** - Leave project

**project delete <name>** - Delete local chain

```
--silent             Delete without prompt
```

**project dissolve <name>** - Dissolve project

```
--reason <text>      Dissolution reason
```

**project pending** - Show pending proposals

**project approve <id>** - Approve proposal

**project deny <id>** - Deny proposal

**project log** - Show chain history

**project link <name>** - Link directory to project

**project env list** - List environments

**project env add <name>** - Add environment

**project env remove <name>** - Remove environment

```
--force              Force remove and revoke access
```

### env

**env use <name>** - Switch environment

**env list** - List environments

**env unlock** - Write variables to .env

**env lock** - Remove .env file

**env export** - Export as shell commands

**env var list** - List variables

```
--env <name>         Environment (default: current)
--json               Output as JSON
```

**env var set <KEY=value>** - Set variable

```
--env <name>         Environment (default: current)
```

**env var get <KEY>** - Get variable value

**env var delete <KEY>** - Delete variable

**env history** - View change history

```
--key <name>         Filter by variable
--author <name>      Filter by author
```

### peers

**peers list** - List connected peers

```
--json               Output as JSON
```

**peers add <address>** - Add peer manually

**peers remove <fingerprint>** - Remove peer

### log

**log** - View logs

```
--level <level>      Filter: debug, info, warn, error
--since <duration>   Show since (default: 24h)
--until <duration>   Show until
--category <cat>     Filter: identity, project, secrets
--project <name>     Filter by project
--search <text>      Search logs
--format <fmt>       Format: tui, table, json (default: tui)
--follow             Follow new logs (like tail -f)
--limit <count>      Max entries (default: 1000)
```

### Other Commands

**status** - Show current status

**whoami** - Show identity

```
--pubkey             Show public key only
--json               Output as JSON
```

**version** - Show version

**ui** - Open web UI

```
--no-open            Print URL instead of opening browser
```

**doctor** - Run diagnostics

## Configuration Defaults

### Daemon Defaults

| Setting | Default |
|---------|---------|
| P2P Port | 7834 |
| Web Port | 7835 |
| Web Enabled | true |
| mDNS Discovery | true |
| Log Level | info |
| Log Format | text |

### Project Defaults

| Setting | Default |
|---------|---------|
| Environments | dev, stage, prod |
| Auto-lock Timeout | 480 minutes (8 hours) |
| Default Role | member |
| Invite TTL | 10 minutes |

### Environment Detection

When creating a project, envctl auto-detects environments from `.env.*` files:

| File Pattern | Detected As |
|--------------|-------------|
| `.env.local` | local |
| `.env.development` | dev |
| `.env.dev` | dev |
| `.env.test` | test |
| `.env.staging` | stage |
| `.env.stage` | stage |
| `.env.production` | prod |
| `.env.prod` | prod |

Skipped patterns: `.env.example`, `.env.sample`, `.env.template`

## Validation Rules

### Identity Name

- 1-64 characters
- Alphanumeric, hyphens, underscores
- Cannot be empty

### Environment Name

- 1-32 characters
- Lowercase alphanumeric + hyphens
- Must start with letter
- Pattern: `^[a-z][a-z0-9-]{0,31}$`

### Ports

- Range: 1-65535

### Log Levels

- `debug` - Verbose debugging
- `info` - Normal operation
- `warn` - Warnings
- `error` - Errors only

## Example Configurations

### Minimal Setup

```toml
# ~/.config/envctl/config.toml
[identity]
name = "alice"

[daemon]
p2p_port = 7834
```

### Team with Manual Peers

```toml
# ~/.config/envctl/config.toml
[identity]
name = "alice"

[daemon]
p2p_port = 7834
web_port = 7835

[discovery]
mdns = true
manual_peers = [
    "10.0.0.50:7834",
    "10.0.0.51:7834"
]

[defaults]
team = "backend-api"
```

### Production Server

```toml
# ~/.config/envctl/config.toml
[identity]
name = "prod-server-1"

[daemon]
p2p_port = 7834
web_enabled = false

[discovery]
mdns = false
manual_peers = ["secrets.internal:7834"]

[logging]
level = "warn"
format = "json"
```

### CI/CD Environment

```bash
# Set config directory for isolation
export ENVCTL_CONFIG_DIR=/tmp/envctl-ci

# Initialize identity non-interactively
echo "$IDENTITY_PASSPHRASE" | envctl identity init --name ci-runner

# Start daemon
envctl daemon start

# Unlock and use
envctl env unlock
source .env
```
