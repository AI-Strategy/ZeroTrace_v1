use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use uuid::Uuid;

/// Verifies that a volume mount point exists and is writable.
/// Used for V56 "Path Jail" pre-flight checks.
pub fn verify_volume_mount(mount_path: &str) -> Result<(), String> {
    let path = Path::new(mount_path);

    // 1. Check if the directory exists
    if !path.exists() {
        return Err(format!("V56_CRITICAL: Mount point {} does not exist.", mount_path));
    }

    // 2. Perform 'Canary Write' to verify permissions
    let canary_id = Uuid::new_v4().to_string();
    let canary_path = path.join(format!(".health_canary_{}", canary_id));

    {
        let mut file = File::create(&canary_path)
            .map_err(|e| format!("V56_PERM_DENIED: Cannot create file in {}. Error: {}", mount_path, e))?;
        
        file.write_all(canary_id.as_bytes())
            .map_err(|e| format!("V56_WRITE_FAIL: Failed to write to volume. Error: {}", e))?;
    }

    // 3. Perform 'Integrity Read'
    let mut buffer = String::new();
    let mut file = File::open(&canary_path).map_err(|_| "V56_READ_FAIL: Failed to reopen canary file.")?;
    file.read_to_string(&mut buffer).map_err(|_| "V56_READ_FAIL: Failed to read canary file.")?;

    if buffer != canary_id {
        return Err("V56_CORRUPTION: Volume write/read mismatch detected.".into());
    }

    // 4. Cleanup
    fs::remove_file(&canary_path).map_err(|_| "V56_CLEANUP_FAIL: Could not delete canary file.")?;

    println!("VOL_HEALTH_OK: Verified persistent mount at {}", mount_path);
    Ok(())
}
