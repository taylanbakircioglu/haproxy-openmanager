# HAProxy Agent Utilities

This directory contains utility scripts for managing HAProxy agents.

## Agent Uninstall Scripts

Complete agent removal scripts that clean up all agent components while leaving HAProxy installation untouched.

### macOS Uninstall Script

**File:** `uninstall-agent-macos.sh`

**Usage:**
```bash
sudo ./uninstall-agent-macos.sh
```

**Features:**
- ✅ Terminates all agent processes (including daemon mode)
- ✅ Stops and removes all launchd services
- ✅ Removes agent binaries from all possible locations
- ✅ Cleans up configuration and log directories
- ✅ Removes temporary files and sockets
- ✅ Comprehensive verification with detailed reporting
- ✅ HAProxy installation remains untouched

**Process Patterns Handled:**
- `haproxy-agent`
- `/usr/local/bin/haproxy-agent`
- `/opt/homebrew/bin/haproxy-agent`
- `com.haproxy.agent`
- `haproxy-agent daemon`
- `bash.*haproxy-agent`
- `nohup.*haproxy-agent`

### Linux Uninstall Script

**File:** `uninstall-agent-linux.sh`

**Usage:**
```bash
sudo ./uninstall-agent-linux.sh
```

**Features:**
- ✅ Terminates all agent processes (including daemon mode)
- ✅ Stops, disables, and masks systemd services
- ✅ Removes agent binaries from all possible locations
- ✅ Cleans up configuration and log directories
- ✅ Removes temporary files and sockets
- ✅ Cleans agent-related cron jobs
- ✅ Reloads systemd daemon
- ✅ Comprehensive verification with detailed reporting
- ✅ HAProxy installation remains untouched

**Process Patterns Handled:**
- `haproxy-agent`
- `/usr/local/bin/haproxy-agent`
- `/usr/bin/haproxy-agent`
- `haproxy-agent.service`
- `haproxy-agent daemon`
- `bash.*haproxy-agent`
- `nohup.*haproxy-agent`

## What Gets Cleaned Up

### Both Scripts Remove:

**Processes:**
- All haproxy-agent processes (normal and daemon mode)
- Background processes started with nohup
- Service-managed processes

**Services:**
- **macOS:** launchd services (com.haproxy.agent, etc.)
- **Linux:** systemd services (haproxy-agent.service, etc.)

**Files and Directories:**
- Agent binaries in all standard locations
- Configuration directories (`/etc/haproxy-agent`, etc.)
- Log directories (`/var/log/haproxy-agent`, etc.)
- PID files (`/var/run/haproxy-agent.pid`, etc.)
- Temporary files and sockets
- Service definition files (plist/service files)

**Additional Linux Cleanup:**
- Agent-related cron jobs
- Systemd service masks and resets

## What Remains Untouched

- ✅ HAProxy installation and binaries
- ✅ HAProxy configuration files
- ✅ HAProxy service/daemon
- ✅ HAProxy logs
- ✅ System HAProxy packages

## Verification

Both scripts provide comprehensive verification:

- **Process Check:** Ensures no agent processes remain
- **Service Check:** Verifies no agent services are loaded
- **Binary Check:** Confirms all agent binaries are removed
- **Detailed Reporting:** Shows any remaining components

## Usage Examples

### Complete Agent Removal (macOS)
```bash
# Download and run the script
sudo ./uninstall-agent-macos.sh

# Verify cleanup
ps aux | grep haproxy-agent
launchctl list | grep haproxy
```

### Complete Agent Removal (Linux)
```bash
# Download and run the script
sudo ./uninstall-agent-linux.sh

# Verify cleanup
ps aux | grep haproxy-agent
systemctl list-units | grep haproxy-agent
systemctl status haproxy-agent  # Should show "Unit not found"
```

## Notes

- **Root Required:** Both scripts require root permissions
- **Safe Operation:** HAProxy service remains completely untouched
- **Daemon Mode Support:** Handles modern daemon-mode agents
- **Deep Cleanup:** Uses both targeted and deep search methods
- **Comprehensive:** Covers all possible agent installation patterns
- **Verification:** Provides detailed cleanup verification

## Troubleshooting

If the script reports remaining components:

1. **Remaining Processes:** Check the process list and manually kill if needed
2. **Remaining Services:** Manually stop/disable services if needed
3. **Remaining Binaries:** Check the reported locations and remove manually

The scripts are designed to handle all common scenarios, but in rare cases manual cleanup may be needed for custom installations.
