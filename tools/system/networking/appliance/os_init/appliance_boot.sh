#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Enterprise bunyanx - Appliance Safe Boot Manager
# ═══════════════════════════════════════════════════════════════════
# This script runs during systemd early boot (network-pre.target).
# It enforces a strict boot counter to protect against bricking.
# If the firewall fails to boot network configurations successfully 
# 3 times consecutively, it enters SAFE MODE.
# 
# Safe Mode: Flushes nftables, applies a minimal whitelist for MGMT.
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

BOOT_COUNTER_FILE="/etc/bunyanx/boot_counter"
SAFE_MODE_FLAG="/etc/bunyanx/SAFE_MODE_ACTIVE"
MAX_FAILURES=3

# Ensure directory exists
mkdir -p /etc/bunyanx

# Read current failures
FAILURES=0
if [ -f "$BOOT_COUNTER_FILE" ]; then
    FAILURES=$(cat "$BOOT_COUNTER_FILE")
fi

echo "bunyanx Boot Manager: Previous boot failures: $FAILURES"

if [ "$FAILURES" -ge "$MAX_FAILURES" ]; then
    echo "🚨 CRITICAL: Boot failures reached $MAX_FAILURES. Entering SAFE MODE."
    touch "$SAFE_MODE_FLAG"
    
    # Apply minimal atomic nftables rule for Safe Mode
    cat > /tmp/safemode.nft << 'EOF'
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established and related connections
        ct state established,related accept

        # Safe Mode: Allow SSH and Web UI locally (Assuming MGMT is up)
        tcp dport { 22, 8888, 443 } accept

        # Allow internal loopback
        iif "lo" accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
    
    # Load safe mode rules atomically
    nft -f /tmp/safemode.nft
    
    echo "✅ Safe mode nftables rules applied. MGMT access secured."
    exit 0
else
    # Increment counter (the main application will reset it to 0 upon successful init)
    NEXT_FAIL=$((FAILURES + 1))
    echo "$NEXT_FAIL" > "$BOOT_COUNTER_FILE"
    
    # Remove safe mode flag if it exists
    rm -f "$SAFE_MODE_FLAG"
    
    echo "✅ Boot counter incremented. Proceeding to normal initialization."
    exit 0
fi
