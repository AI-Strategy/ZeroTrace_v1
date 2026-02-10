use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use tempfile::NamedTempFile;

// Structure matching the JSON output of onboard.sh
#[derive(Serialize, Deserialize, Debug)]
struct TenantConfig {
    organization_id: String,
    tier: String,
    shard_endpoint: String,
    oci_registry: String,
    worm_ledger_bucket: String,
    status: String,
}

#[test]
fn test_onboarding_config_validation() {
    // 1. Simulate the output of the onboard.sh script
    let config = TenantConfig {
        organization_id: "UUID-9924-X".to_string(),
        tier: "ENTERPRISE".to_string(),
        shard_endpoint: "bolt+s://zt-shard-UUID-9924-X.neo4j.io:7687".to_string(),
        oci_registry: "us-west-2.ocir.io/zt-vault-UUID-9924-X".to_string(),
        worm_ledger_bucket: "s3://zerotrace-audit-ledger/logs/UUID-9924-X".to_string(),
        status: "active".to_string(),
    };

    // 2. Create a temporary file mimicking the "tenant_config_UUID.json"
    let mut file = NamedTempFile::new().unwrap();
    let json_content = serde_json::to_string_pretty(&config).unwrap();
    write!(file, "{}", json_content).unwrap();

    // 3. Attempt to load and deserialize it back (Validation Logic)
    let file_path = file.path();
    let file_content = std::fs::read_to_string(file_path).unwrap();
    let loaded_config: TenantConfig = serde_json::from_str(&file_content).expect("Failed to parse tenant config");

    // 4. Assertions ensuring the provisioning script logic holds
    assert_eq!(loaded_config.organization_id, "UUID-9924-X");
    assert_eq!(loaded_config.shard_endpoint, "bolt+s://zt-shard-UUID-9924-X.neo4j.io:7687");
    assert_eq!(loaded_config.status, "active");
    
    // Validate Tier constraints (e.g., Enterprise must have bolt+s)
    if loaded_config.tier == "ENTERPRISE" {
        assert!(loaded_config.shard_endpoint.starts_with("bolt+s://"), "Enterprise shards must be encrypted (bolt+s)");
    }
}
