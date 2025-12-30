# envctl Web UI

The envctl web UI provides a browser-based interface for monitoring and managing your envctl daemon, projects, peers, and requests.

## Accessing the Web UI

Start the web UI by running:

```bash
envctl ui
```

This opens your default browser to the web interface (typically `http://localhost:7835`).

To just print the URL without opening a browser:

```bash
envctl ui --no-open
```

The web UI is served by the daemon, so the daemon must be running:

```bash
envctl daemon start
envctl ui
```

## Dashboard

The dashboard provides an at-a-glance overview of your envctl status.

### Stats Panel

- **Connected Peers** - Number of currently connected peers
- **Projects** - Number of projects you're a member of
- **Uptime** - How long the daemon has been running

### Status Table

| Field | Description |
|-------|-------------|
| Identity | Your identity display name |
| Fingerprint | Your identity's cryptographic fingerprint |
| PID | Daemon process ID |
| Started | When the daemon was started |

The dashboard updates in real-time via WebSocket when peers connect/disconnect or chains are reloaded.

## Projects

The Projects page lets you browse your projects and view their members.

### Projects List

Shows all active projects (dissolved projects are hidden) as cards displaying:

- Project name
- Member count
- Block count (chain length)
- Available environments (dev, stage, prod, etc.)

Click a project card to view its details.

### Project Detail View

When viewing a project, you'll see:

**Members Table**
| Column | Description |
|--------|-------------|
| Name | Member's identity name |
| Role | `admin` or `member` (color-coded) |
| Environments | Which environments they can access |
| Joined | When they joined the project |

**Environments**
List of available environments for this project.

**Info**
- Block count
- Project status

Click the back button to return to the projects list.

## Requests

The Requests page shows pending environment variable requests from other team members.

### Pending Requests Table

| Column | Description |
|--------|-------------|
| From | Who is requesting access |
| Environment | Which environment they're requesting (color-coded by sensitivity) |
| Requested | How long ago the request was made |
| Actions | Approve or Deny buttons |

**Environment Colors:**
- Green - Development environments (dev, local)
- Yellow - Staging environments (stage, staging)
- Red - Production environments (prod, production)

### Approving Requests

Click **Approve** to share your environment variables with the requester. The variables are encrypted specifically to their public key and sent directly.

Click **Deny** to reject the request.

## Peers

The Peers page shows network connectivity status and lets you manage peer connections.

### Connected Peers Table

| Column | Description |
|--------|-------------|
| Name | Peer's identity name |
| Address | Network address (host:port) |
| Status | `connected` (green) or `disconnected` (red) |
| Teams | Projects you share with this peer |
| Last Seen | When this peer was last active |

### Adding Peers Manually

Click **Add Peer** and enter the peer's address in `host:port` format:

```
192.168.1.100:7834
peer.example.com:7834
```

Peers on the same local network are discovered automatically via mDNS. Manual peer addition is useful for:
- Peers on different networks (VPN, remote)
- Environments where mDNS is disabled
- Tailscale or other overlay networks

## Members

The Members page provides a detailed view of project members with real-time online status.

### Features

- **Project Selector** - Switch between projects to view their members
- **Online Status** - Green dot for online members, gray for offline
- **Auto-refresh** - Member status refreshes every 30 seconds
- **Real-time Updates** - Instant updates when peers connect/disconnect

### Member Card

Each member shows:
- Online/offline status indicator (with glow effect when online)
- Name (with "you" badge for your own identity)
- Fingerprint (cryptographic identifier)
- Environment access badges
- Role badge (admin = yellow, member = gray)
- Last seen timestamp (or "Online" if currently connected)

Click **Refresh** to manually update the member list.

## Logs

The Logs page provides a searchable, filterable view of daemon logs.

### Filters

**Level Filter**
- All - Show all log levels
- Debug - Verbose debugging information
- Info - Normal operational messages
- Warn - Warning conditions
- Error - Error conditions

**Time Range**
- Last 5 minutes
- Last 15 minutes
- Last hour
- Last 24 hours
- All

**Search**
Free-text search across log messages and fields. Matches are highlighted.

### Log Table

| Column | Description |
|--------|-------------|
| Time | When the log entry was created |
| Level | DEBUG, INFO, WARN, or ERROR (color-coded) |
| Message | The log message |
| Details | Key-value fields (truncated preview) |

Click any row to expand it and see the full JSON log entry.

### Actions

- **Refresh** - Reload logs from the daemon
- **Export** - Download filtered logs as JSON

### Status Bar

Shows:
- Number of entries currently displayed
- Error and warning counts
- Buffer usage (current / max entries)

## Real-Time Updates

The web UI maintains a WebSocket connection to the daemon for real-time updates:

| Event | Effect |
|-------|--------|
| `chains.reloaded` | Dashboard and Projects refresh |
| `peer_connected` | Dashboard, Members, and Peers refresh |
| `peer_disconnected` | Dashboard, Members, and Peers refresh |

A connection status indicator in the sidebar shows:
- **Green** - Connected to daemon
- **Red** - Disconnected (will auto-reconnect)

## Configuration

The web UI is enabled by default. To disable it, set in your config:

```toml
# ~/.config/envctl/config.toml
[daemon]
web_enabled = false
```

To change the web UI port:

```toml
[daemon]
web_port = 8080
```

Or via command line when running the daemon:

```bash
envctl daemon run --web-port 8080
```

## Security

The web UI:
- Only listens on localhost by default
- Requires the daemon to be running
- Does not expose any endpoints externally
- All operations go through the daemon's authentication

To access the web UI remotely (not recommended), you would need to set up SSH port forwarding or a reverse proxy with authentication.

## Troubleshooting

### Web UI Won't Load

1. Check if the daemon is running:
   ```bash
   envctl daemon status
   ```

2. Check if web UI is enabled:
   ```bash
   grep web_enabled ~/.config/envctl/config.toml
   ```

3. Check if the port is in use:
   ```bash
   lsof -i :7835
   ```

### WebSocket Disconnects

The UI will automatically reconnect. If disconnections persist:

1. Check daemon logs:
   ```bash
   envctl log --since 5m
   ```

2. Restart the daemon:
   ```bash
   envctl daemon stop
   envctl daemon start
   ```

### Stale Data

Click the refresh button on any page, or the data will auto-refresh on relevant events.
