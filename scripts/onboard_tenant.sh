#!/bin/bash
# ZeroTrace Tenant Onboarding Script v1.0
# Automates Security Cell Provisioning

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ORGANIZATION_NAME>"
    exit 1
fi

ORG_NAME=$1
ORG_ID=$(uuidgen)
SHARD_PORT=$((7687 + $(shuf -i 1-1000 -n 1))) # Mock dynamic port allocation

echo ">>> Starting Onboarding for Organization: $ORG_NAME"
echo ">>> Assigned Organization ID: $ORG_ID"

# 1. Provision Neo4j Shard (Mock)
echo ">>> [1/3] Provisioning isolated Neo4j Shard..."
# In prod: helm install neo4j-shard-$ORG_ID ...
echo "    -> Shard 'neo4j-$ORG_ID' created on port $SHARD_PORT."
echo "    -> Applying 'Reasoning Baseline' schema... DONE."

# 2. Provision OCI Registry (Mock)
echo ">>> [2/3] Creating Private OCI Registry for Agentic Tools..."
# In prod: aws ecr create-repository --repository-name zerotrace/$ORG_ID/tools ...
echo "    -> Registry 'zerotrace/$ORG_ID/tools' ready."
echo "    -> Lockdown Policy: 'SCAN_ON_PUSH=Enabled'."

# 3. Generate API Keys & Config
API_KEY=$(openssl rand -hex 32)
echo ">>> [3/3] Generating Access Credentials..."
echo "    -> API_KEY: $API_KEY"
echo "    -> WORM_LEDGER_PATH: s3://zerotrace-logs/$ORG_ID/"

# 4. Final Output
cat <<EOF > tenant_config_$ORG_NAME.json
{
  "organization_name": "$ORG_NAME",
  "organization_id": "$ORG_ID",
  "shard_endpoint": "neo4j://shard-$ORG_ID:$SHARD_PORT",
  "oci_registry": "zerotrace/$ORG_ID/tools",
  "api_key": "$API_KEY",
  "status": "active"
}
EOF

echo ">>> Onboarding Complete. Configuration saved to tenant_config_$ORG_NAME.json"
echo ">>> Please securely transmit these credentials to the client."
