#!/bin/bash

echo "=== Updating Agent Scripts to New Version with STATS Collection ==="
echo ""

# Get admin token
echo "Step 1: Getting admin token..."
TOKEN=$(curl -k -s -X POST "https://haproxy-openmanager.example.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "❌ ERROR: Could not get admin token"
    exit 1
fi

echo "✅ Got token: ${TOKEN:0:20}..."
echo ""

# Update Linux agent version to 1.0.3
echo "Step 2: Creating new version 1.0.3 for Linux..."
LINUX_RESPONSE=$(curl -k -s -X POST "https://haproxy-openmanager.example.com/api/config/agent-versions/linux" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "version": "1.0.3",
    "changelog": [
      "Added HAProxy stats collection for dashboard",
      "Fixed lazy initialization for SOCAT_BIN and STATS_SOCKET_PATH",
      "Enhanced logging for stats collection debugging",
      "Resolves dashboard showing no data after agent auto-upgrade"
    ]
  }')

echo "Linux response:"
echo "$LINUX_RESPONSE" | jq .
echo ""

# Update macOS agent version to 1.0.3
echo "Step 3: Creating new version 1.0.3 for macOS..."
MACOS_RESPONSE=$(curl -k -s -X POST "https://haproxy-openmanager.example.com/api/config/agent-versions/macos" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "version": "1.0.3",
    "changelog": [
      "Added HAProxy stats collection for dashboard",
      "Fixed lazy initialization for SOCAT_BIN and STATS_SOCKET_PATH",
      "Enhanced logging for stats collection debugging",
      "Resolves dashboard showing no data after agent auto-upgrade"
    ]
  }')

echo "macOS response:"
echo "$MACOS_RESPONSE" | jq .
echo ""

echo "=== Version update complete ==="
echo ""
echo "IMPORTANT: Now you need to sync the script files from backend to database:"
echo ""
echo "Option 1 - Use UI:"
echo "  1. Go to Agent Management page"
echo "  2. Click 'Settings' or 'Manage Versions'"
echo "  3. Click 'Edit Script' for Linux and macOS"
echo "  4. Save without changes (this will sync file content to database)"
echo ""
echo "Option 2 - Use API (RECOMMENDED):"
echo "  Run this command to sync scripts from files to database:"
echo ""
echo "  curl -k -X POST 'https://haproxy-openmanager.example.com/api/agents/sync-scripts-from-files' \\"
echo "    -H 'Authorization: Bearer $TOKEN'"
echo ""
echo "After syncing, trigger agent upgrade:"
echo "  1. Go to Agent Management page"
echo "  2. Select demo-agent"
echo "  3. Click 'Upgrade' button"
echo "  4. Wait for agent to restart (30 seconds)"
echo "  5. Check backend logs for 'Has haproxy_stats_csv: True'"

