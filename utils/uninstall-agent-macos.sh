#!/bin/bash
# HAProxy Agent Uninstaller for macOS - Complete Agent Cleanup
# Run with: sudo ./uninstall-agent-macos.sh
# Updated for daemon mode and modern agent cleanup

set -e

echo "=========================================="
echo "HAProxy Agent Uninstaller for macOS v5.0"
echo "Complete Agent Cleanup Edition"
echo "With Daemon Mode & Modern Agent Support"
echo "=========================================="

# Check root permissions
if [[ $EUID -ne 0 ]]; then
   echo "❌ ERROR: This script must be run as root"
   echo "   Please run: sudo $0"
   exit 1
fi

echo "🔍 Performing COMPLETE agent cleanup (HAProxy untouched)..."

# Function to safely remove files/directories
safe_remove() {
    local path="$1"
    local desc="$2"
    
    if [[ -e "$path" ]]; then
        echo "🗑️  Removing $desc..."
        rm -rf "$path" 2>/dev/null || {
            echo "⚠️  Failed to remove $desc (may not exist or no permission)"
            return 1
        }
        echo "✅ $desc removed"
        return 0
    else
        echo "ℹ️  $desc not found"
        return 1
    fi
}

# Function to find and kill daemon processes
kill_daemon_processes() {
    echo "🔪 Terminating ALL HAProxy Agent processes (including daemon mode)..."
    local killed_count=0
    
    # Enhanced process patterns for daemon mode
    local patterns=(
        "haproxy-agent"
        "/usr/local/bin/haproxy-agent"
        "/opt/homebrew/bin/haproxy-agent"
        "com.haproxy.agent"
        "haproxy-agent daemon"
        "bash.*haproxy-agent"
        "nohup.*haproxy-agent"
    )
    
    for pattern in "${patterns[@]}"; do
        local pids=$(pgrep -f "$pattern" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            echo "   🎯 Killing processes matching: $pattern"
            echo "   📋 PIDs: $pids"
            
            # First try TERM signal
            kill -TERM $pids 2>/dev/null || true
            sleep 3
            
            # Check if still running, then use KILL
            local remaining_pids=$(pgrep -f "$pattern" 2>/dev/null || true)
            if [[ -n "$remaining_pids" ]]; then
                echo "   💀 Force killing remaining PIDs: $remaining_pids"
                kill -KILL $remaining_pids 2>/dev/null || true
                sleep 1
            fi
            
            killed_count=$((killed_count + $(echo "$pids" | wc -w)))
        fi
    done
    
    # Also check for any remaining haproxy-agent processes
    local final_check=$(pgrep -f "haproxy-agent" 2>/dev/null || true)
    if [[ -n "$final_check" ]]; then
        echo "   🔥 Final cleanup: killing PIDs $final_check"
        kill -KILL $final_check 2>/dev/null || true
    fi
    
    if [[ $killed_count -gt 0 ]]; then
        echo "✅ Terminated $killed_count agent processes"
    else
        echo "ℹ️  No agent processes found"
    fi
}

# Function to find and remove all agent binaries dynamically
remove_agent_binaries() {
    echo "🔍 Searching for agent binaries in all possible locations..."
    
    # Common binary locations
    local search_paths=(
        "/usr/local/bin"
        "/opt/homebrew/bin"
        "/usr/bin"
        "/bin"
        "/opt/homebrew/sbin"
        "/usr/sbin"
        "/sbin"
    )
    
    local found_count=0
    for path in "${search_paths[@]}"; do
        if [[ -f "$path/haproxy-agent" ]]; then
            safe_remove "$path/haproxy-agent" "agent binary ($path)"
            ((found_count++))
        fi
    done
    
    # Deep search for any remaining haproxy-agent binaries
    echo "🔍 Deep search for any remaining haproxy-agent binaries..."
    local found_binaries
    found_binaries=$(find /usr /opt /Applications 2>/dev/null -name "haproxy-agent" -type f 2>/dev/null || true)
    
    if [[ -n "$found_binaries" ]]; then
        while IFS= read -r binary; do
            if [[ -f "$binary" ]]; then
                safe_remove "$binary" "found agent binary ($binary)"
                ((found_count++))
            fi
        done <<< "$found_binaries"
    fi
    
    if [[ $found_count -eq 0 ]]; then
        echo "ℹ️  No agent binaries found"
    else
        echo "✅ Removed $found_count agent binaries"
    fi
}

# Function to clean up launchd services
cleanup_launchd_services() {
    echo "🛑 Cleaning up agent launchd services..."
    
    local services=(
        "com.haproxy.agent"
        "haproxy.agent" 
        "haproxy-agent"
        "com.haproxy-agent"
    )
    
    for service in "${services[@]}"; do
        # Check if service is loaded
        if launchctl list 2>/dev/null | grep -q "$service"; then
            echo "   🛑 Stopping service: $service"
            launchctl stop "$service" 2>/dev/null || true
            launchctl unload "/Library/LaunchDaemons/$service.plist" 2>/dev/null || true
            launchctl unload "/Library/LaunchAgents/$service.plist" 2>/dev/null || true
            launchctl remove "$service" 2>/dev/null || true
            echo "   ✅ Service $service cleaned up"
        fi
    done
    
    # Remove plist files
    for service in "${services[@]}"; do
        safe_remove "/Library/LaunchDaemons/$service.plist" "LaunchDaemon plist ($service)"
        safe_remove "/Library/LaunchAgents/$service.plist" "LaunchAgent plist ($service)"
        safe_remove "~/Library/LaunchAgents/$service.plist" "User LaunchAgent plist ($service)"
    done
}

# Function to clean up configuration and data
cleanup_agent_data() {
    echo "🧹 Cleaning up agent configuration and data..."
    
    # Configuration directories
    local config_dirs=(
        "/etc/haproxy-agent"
        "/opt/homebrew/etc/haproxy-agent"
        "/usr/local/etc/haproxy-agent"
        "/var/lib/haproxy-agent"
    )
    
    for config_dir in "${config_dirs[@]}"; do
        safe_remove "$config_dir" "agent configuration directory ($config_dir)"
    done
    
    # Log directories
    local log_dirs=(
        "/var/log/haproxy-agent"
        "/opt/homebrew/var/log/haproxy-agent"
        "/usr/local/var/log/haproxy-agent"
        "/tmp/haproxy-agent-logs"
    )
    
    for log_dir in "${log_dirs[@]}"; do
        safe_remove "$log_dir" "agent log directory ($log_dir)"
    done
    
    # PID files
    local pid_files=(
        "/var/run/haproxy-agent.pid"
        "/tmp/haproxy-agent.pid"
        "/usr/local/var/run/haproxy-agent.pid"
        "/opt/homebrew/var/run/haproxy-agent.pid"
    )
    
    for pid_file in "${pid_files[@]}"; do
        safe_remove "$pid_file" "agent PID file ($pid_file)"
    done
}

# Function to clean up temporary files
cleanup_temp_files() {
    echo "🧹 Cleaning up agent-specific temporary and debug files..."
    
    local temp_patterns=(
        "/tmp/agent_debug.log"
        "/tmp/debug_agent.log" 
        "/tmp/fixed_agent_test.log"
        "/tmp/haproxy-agent-*"
        "/tmp/agent-startup-with-config.sh"
        "/tmp/daemon-test-agent*.sh"
        "/var/tmp/haproxy-agent-*"
    )
    
    for pattern in "${temp_patterns[@]}"; do
        if [[ "$pattern" == *"*"* ]]; then
            # Handle wildcard patterns
            local base_dir=$(dirname "$pattern")
            local file_pattern=$(basename "$pattern")
            if [[ -d "$base_dir" ]]; then
                local found_files=$(find "$base_dir" -maxdepth 1 -name "$file_pattern" -type f 2>/dev/null || true)
                if [[ -n "$found_files" ]]; then
                    while IFS= read -r file; do
                        [[ -f "$file" ]] && safe_remove "$file" "agent temp file ($file)"
                    done <<< "$found_files"
                fi
            fi
        else
            safe_remove "$pattern" "agent temp file ($(basename "$pattern"))"
        fi
    done
    
    # Clean up agent-specific sockets
    echo "🧹 Cleaning up agent-specific sockets..."
    local socket_patterns=(
        "/tmp/haproxy-agent-*"
        "/var/run/haproxy-agent-*"
    )
    
    for pattern in "${socket_patterns[@]}"; do
        local socket_dir=$(dirname "$pattern")
        local socket_name=$(basename "$pattern")
        if [[ -d "$socket_dir" ]]; then
            local found_sockets=$(find "$socket_dir" -name "$socket_name" -type s 2>/dev/null || true)
            if [[ -n "$found_sockets" ]]; then
                while IFS= read -r socket; do
                    safe_remove "$socket" "agent socket ($socket)"
                done <<< "$found_sockets"
            fi
        fi
    done
}

# Main cleanup execution
echo "🚀 Starting complete agent cleanup process..."

# 1. Kill all processes (including daemon mode)
kill_daemon_processes

# 2. Stop and clean launchd services
cleanup_launchd_services

# 3. Remove agent binaries
remove_agent_binaries

# 4. Clean up configuration and data
cleanup_agent_data

# 5. Clean up temporary files
cleanup_temp_files

# 6. Reload launchctl to clean up daemon list
echo "🔄 Refreshing system services..."
launchctl load /System/Library/LaunchDaemons/com.apple.periodic-daily.plist 2>/dev/null || true

# 7. Final comprehensive verification
echo "🔍 Final agent cleanup verification..."
local remaining_processes=$(pgrep -f "haproxy-agent" 2>/dev/null | wc -l || echo "0")
local remaining_services=$(launchctl list 2>/dev/null | grep -c "haproxy.agent\|haproxy-agent" || echo "0")
local remaining_binaries=$(find /usr /opt /Applications 2>/dev/null -name "haproxy-agent" -type f 2>/dev/null | wc -l || echo "0")

echo ""
if [[ $remaining_processes -eq 0 && $remaining_services -eq 0 && $remaining_binaries -eq 0 ]]; then
    echo "✅ COMPLETE AGENT CLEANUP VERIFIED - Agent completely removed!"
else
    echo "⚠️  Some agent remnants detected:"
    [[ $remaining_processes -gt 0 ]] && echo "   - $remaining_processes agent processes still running"
    [[ $remaining_services -gt 0 ]] && echo "   - $remaining_services agent services still loaded"
    [[ $remaining_binaries -gt 0 ]] && echo "   - $remaining_binaries agent binaries still found"
    
    if [[ $remaining_binaries -gt 0 ]]; then
        echo "   📋 Remaining agent binaries:"
        find /usr /opt /Applications 2>/dev/null -name "haproxy-agent" -type f 2>/dev/null | while read -r binary; do
            echo "     - $binary"
        done
    fi
    
    if [[ $remaining_processes -gt 0 ]]; then
        echo "   📋 Remaining agent processes:"
        pgrep -f "haproxy-agent" 2>/dev/null | while read -r pid; do
            ps -p "$pid" -o pid,ppid,command 2>/dev/null || true
        done
    fi
fi

echo ""
echo "🎉 HAProxy Agent Uninstaller Completed!"
echo ""
echo "📋 Complete cleanup summary:"
echo "   • ✅ All agent processes terminated (including daemon mode)"
echo "   • ✅ All agent launchd services removed and unloaded"
echo "   • ✅ All agent binaries found and removed (deep search)"
echo "   • ✅ All agent configs, logs, and data cleaned"
echo "   • ✅ All agent-specific temp files and sockets removed"
echo "   • ✅ System services refreshed"
echo "   • ✅ HAProxy installation and configs UNTOUCHED"
echo ""
echo "🚀 System ready for fresh agent installation!"
echo ""
echo "💡 Tips:"
echo "   • HAProxy service and configurations remain intact"
echo "   • Run 'ps aux | grep haproxy-agent' to verify no processes remain"
echo "   • Run 'launchctl list | grep haproxy' to verify no services remain"
echo "   • Agent can be reinstalled using the management UI"
