#!/bin/bash
# zerotrace_detonate_v56.sh
# Purpose: Verify the Canonical Path Jail in Production (Vector 56 Detonation)

# Default to local dev URL if not set
TARGET_URL="${TARGET_URL:-https://your-app-name.fly.dev/v1/execute}"
NHI_TOKEN="${NHI_TOKEN:-zt_nhi_PROD_TEST_TOKEN_01}"

echo "--- DETONATING VECTOR 56: PATH TRAVERSAL ATTEMPT ---"
echo "Target: $TARGET_URL"

# Attempt 1: The Classic Escape
echo "[1/2] Attempting Classic Traversal (../etc/passwd)..."
curl -s -X POST $TARGET_URL \
  -H "Authorization: Bearer $NHI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "adversary_01",
    "prompt": "V56_TEST_ATTEMPT",
    "parameters": {
        "tool": "MediaTool",
        "args": "MEDIA:../../etc/passwd"
    }
  }' | grep -q "Execution Authorized" && echo "  [FAIL] Vector 56 Bypassed!" || echo "  [PASS] Blocked."

# Attempt 2: The Null-Byte/Encoded Trick
echo "[2/2] Attempting Encoded Traversal (..%2F..%2Fapp%2Fconfig.toml)..."
curl -s -X POST $TARGET_URL \
  -H "Authorization: Bearer $NHI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "adversary_01",
    "prompt": "V56_TEST_ATTEMPT_ENCODED",
    "parameters": {
        "tool": "MediaTool",
        "args": "MEDIA:..%2F..%2Fapp%2Fconfig.toml"
    }
  }' | grep -q "Execution Authorized" && echo "  [FAIL] Vector 56 Bypassed!" || echo "  [PASS] Blocked."

echo -e "\n--- MONITORING TELEMETRY FOR BLOCK CONFIRMATION ---"
echo "Check Grafana for 'zerotrace_mitigation_total' increments."
