use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::Result;

/// Number of overwrite passes before deletion.
const PASSES: usize = 3;

pub fn run(file: &Path) -> Result<()> {
    if !file.exists() {
        eprintln!("error: file not found: {}", file.display());
        std::process::exit(1);
    }

    let len = fs::metadata(file)?.len() as usize;
    if len == 0 {
        fs::remove_file(file)?;
        println!("Deleted: {} (was empty)", file.display());
        return Ok(());
    }

    println!("Shredding {} ({} bytes, {} passes)...", file.display(), len, PASSES);

    // Overwrite with random data, then zeros, then ones, alternating
    let patterns: &[u8] = &[0xAA, 0x55, 0x00];
    for (i, &byte) in patterns[..PASSES.min(patterns.len())].iter().enumerate() {
        let buf = vec![byte; len];
        let mut f = fs::OpenOptions::new().write(true).open(file)?;
        f.write_all(&buf)?;
        f.flush()?;
        f.sync_all()?; // force write to disk before next pass
        println!("  Pass {}/{} complete", i + 1, PASSES);
    }

    fs::remove_file(file)?;

    println!("Deleted:  {}", file.display());
    println!();
    println!("The original file has been securely overwritten and deleted.");
    println!();
    println!("Note: On SSDs/NVMe drives, wear-leveling may preserve copies of the");
    println!("      original data in flash memory. For maximum security, use full-disk");
    println!("      encryption (BitLocker, FileVault, LUKS) on drives containing secrets.");

    Ok(())
}
