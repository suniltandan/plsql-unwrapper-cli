use base64::Engine;
use clap::Parser;
use flate2::read::ZlibDecoder;
use regex::Regex;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Cross-platform CLI tool to unwrap Oracle PL/SQL 10g+ wrapped code
#[derive(Parser)]
#[command(name = "unwrap", version, about)]
struct Cli {
    /// Input file or directory path
    #[arg(short, long)]
    input: PathBuf,

    /// Regex pattern to match input filenames (e.g., "\\.pkw$", "\\.(plb|pkb)$")
    #[arg(short, long)]
    pattern: String,

    /// Output directory (default: same directory as input file)
    #[arg(short, long)]
    output_dir: Option<PathBuf>,
}

/// Oracle 10g+ wrapped code substitution cipher table.
/// Maps byte at index i to CIPHER_TABLE[i].
/// Derived from the octal sequences in unwrap_demo.sh.
const CIPHER_TABLE: [u8; 256] = [
    0x3D, 0x65, 0x85, 0xB3, 0x18, 0xDB, 0xE2, 0x87, 0xF1, 0x52, 0xAB, 0x63, 0x4B, 0xB5, 0xA0,
    0x5F, 0x7D, 0x68, 0x7B, 0x9B, 0x24, 0xC2, 0x28, 0x67, 0x8A, 0xDE, 0xA4, 0x26, 0x1E, 0x03,
    0xEB, 0x17, 0x6F, 0x34, 0x3E, 0x7A, 0x3F, 0xD2, 0xA9, 0x6A, 0x0F, 0xE9, 0x35, 0x56, 0x1F,
    0xB1, 0x4D, 0x10, 0x78, 0xD9, 0x75, 0xF6, 0xBC, 0x41, 0x04, 0x81, 0x61, 0x06, 0xF9, 0xAD,
    0xD6, 0xD5, 0x29, 0x7E, 0x86, 0x9E, 0x79, 0xE5, 0x05, 0xBA, 0x84, 0xCC, 0x6E, 0x27, 0x8E,
    0xB0, 0x5D, 0xA8, 0xF3, 0x9F, 0xD0, 0xA2, 0x71, 0xB8, 0x58, 0xDD, 0x2C, 0x38, 0x99, 0x4C,
    0x48, 0x07, 0x55, 0xE4, 0x53, 0x8C, 0x46, 0xB6, 0x2D, 0xA5, 0xAF, 0x32, 0x22, 0x40, 0xDC,
    0x50, 0xC3, 0xA1, 0x25, 0x8B, 0x9C, 0x16, 0x60, 0x5C, 0xCF, 0xFD, 0x0C, 0x98, 0x1C, 0xD4,
    0x37, 0x6D, 0x3C, 0x3A, 0x30, 0xE8, 0x6C, 0x31, 0x47, 0xF5, 0x33, 0xDA, 0x43, 0xC8, 0xE3,
    0x5E, 0x19, 0x94, 0xEC, 0xE6, 0xA3, 0x95, 0x14, 0xE0, 0x9D, 0x64, 0xFA, 0x59, 0x15, 0xC5,
    0x2F, 0xCA, 0xBB, 0x0B, 0xDF, 0xF2, 0x97, 0xBF, 0x0A, 0x76, 0xB4, 0x49, 0x44, 0x5A, 0x1D,
    0xF0, 0x00, 0x96, 0x21, 0x80, 0x7F, 0x1A, 0x82, 0x39, 0x4F, 0xC1, 0xA7, 0xD7, 0x0D, 0xD1,
    0xD8, 0xFF, 0x13, 0x93, 0x70, 0xEE, 0x5B, 0xEF, 0xBE, 0x09, 0xB9, 0x77, 0x72, 0xE7, 0xB2,
    0x54, 0xB7, 0x2A, 0xC7, 0x73, 0x90, 0x66, 0x20, 0x0E, 0x51, 0xED, 0xF8, 0x7C, 0x8F, 0x2E,
    0xF4, 0x12, 0xC6, 0x2B, 0x83, 0xCD, 0xAC, 0xCB, 0x3B, 0xC4, 0x4E, 0xC0, 0x69, 0x36, 0x62,
    0x02, 0xAE, 0x88, 0xFC, 0xAA, 0x42, 0x08, 0xA6, 0x45, 0x57, 0xD3, 0x9A, 0xBD, 0xE1, 0x23,
    0x8D, 0x92, 0x4A, 0x11, 0x89, 0x74, 0x6B, 0x91, 0xFB, 0xFE, 0xC9, 0x01, 0xEA, 0x1B, 0xF7,
    0xCE,
];

/// Extracts the base64 payload from wrapped PL/SQL source.
///
/// The payload starts after a line matching `^[0-9a-fA-F]+ [0-9a-fA-F]+$`
/// (the hex hash line) and ends at a line matching `^ */ *$` (standalone slash).
fn extract_payload(content: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut payload_start = None;
    let mut payload_end = None;

    // Find the hex line (e.g., "77d9e 1669d") which precedes the base64 payload
    let hex_line_re = Regex::new(r"^[0-9a-fA-F]+ +[0-9a-fA-F]+\s*$").unwrap();
    let slash_re = Regex::new(r"^\s*/\s*$").unwrap();

    for (i, line) in lines.iter().enumerate() {
        if payload_start.is_none() && hex_line_re.is_match(line) {
            payload_start = Some(i + 1); // payload starts on the next line
        } else if payload_start.is_some() && slash_re.is_match(line) {
            payload_end = Some(i);
            break;
        }
    }

    let start = payload_start?;
    let end = payload_end?;

    if start >= end {
        return None;
    }

    Some(lines[start..end].join(""))
}

/// Unwraps a single PL/SQL wrapped file.
///
/// Algorithm:
/// 1. Extract base64 payload (between hex line and standalone `/`)
/// 2. Base64 decode
/// 3. Skip first 20 bytes (Oracle header/hash)
/// 4. Apply substitution cipher
/// 5. zlib decompress
/// 6. Remove null bytes
/// 7. Prepend "CREATE OR REPLACE " (the decompressed body already contains
///    the object type and name, e.g., "PACKAGE BODY foo AS ...")
fn unwrap_content(content: &str) -> Result<String, String> {
    // Step 1: Extract the base64 payload
    let payload = extract_payload(content)
        .ok_or_else(|| "Could not find wrapped payload in file".to_string())?;

    // Step 2: Base64 decode
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&payload)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    // Step 3: Skip first 20 bytes
    if decoded.len() <= 20 {
        return Err("Decoded payload too short (<=20 bytes)".to_string());
    }
    let data = &decoded[20..];

    // Step 4: Apply substitution cipher
    let substituted: Vec<u8> = data.iter().map(|&b| CIPHER_TABLE[b as usize]).collect();

    // Step 5: zlib decompress
    let mut decoder = ZlibDecoder::new(&substituted[..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("Zlib decompression error: {}", e))?;

    // Step 6: Remove null bytes
    decompressed.retain(|&b| b != 0);

    // Step 7: Build the final output
    let body = String::from_utf8_lossy(&decompressed);

    Ok(format!("CREATE OR REPLACE {}\n/\n", body))
}

/// Generates the output path for a given input file.
///
/// Transforms `filename.ext` → `filename_unwrapped.ext`
/// If output_dir is specified, the file is placed there instead.
fn output_path(input: &Path, output_dir: Option<&Path>) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    let ext = input.extension().map(|e| e.to_string_lossy().to_string());

    let new_name = match ext {
        Some(e) => format!("{}_unwrapped.{}", stem, e),
        None => format!("{}_unwrapped", stem),
    };

    let dir = output_dir.unwrap_or_else(|| input.parent().unwrap_or(Path::new(".")));
    dir.join(new_name)
}

/// Process a single file: unwrap and write output.
fn process_file(path: &Path, output_dir: Option<&Path>) -> Result<PathBuf, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let unwrapped = unwrap_content(&content)?;
    let out = output_path(path, output_dir);

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory {}: {}", parent.display(), e))?;
    }

    fs::write(&out, &unwrapped)
        .map_err(|e| format!("Failed to write {}: {}", out.display(), e))?;

    Ok(out)
}

fn main() {
    let cli = Cli::parse();

    // Compile the user-provided regex pattern
    let pattern = Regex::new(&cli.pattern).unwrap_or_else(|e| {
        eprintln!("Error: Invalid regex pattern '{}': {}", cli.pattern, e);
        std::process::exit(1);
    });

    let input = &cli.input;
    let output_dir = cli.output_dir.as_deref();

    if !input.exists() {
        eprintln!("Error: Input path '{}' does not exist", input.display());
        std::process::exit(1);
    }

    let mut success_count = 0u32;
    let mut error_count = 0u32;

    if input.is_file() {
        // Single file mode
        let filename = input.file_name().unwrap_or_default().to_string_lossy();
        if !pattern.is_match(&filename) {
            eprintln!(
                "Warning: File '{}' does not match pattern '{}'",
                filename, cli.pattern
            );
            std::process::exit(1);
        }

        match process_file(input, output_dir) {
            Ok(out) => {
                println!("✓ {} → {}", input.display(), out.display());
                success_count += 1;
            }
            Err(e) => {
                eprintln!("✗ {}: {}", input.display(), e);
                error_count += 1;
            }
        }
    } else if input.is_dir() {
        // Directory mode - walk recursively
        for entry in WalkDir::new(input).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let filename = path.file_name().unwrap_or_default().to_string_lossy();

            if !pattern.is_match(&filename) {
                continue;
            }

            match process_file(path, output_dir) {
                Ok(out) => {
                    println!("✓ {} → {}", path.display(), out.display());
                    success_count += 1;
                }
                Err(e) => {
                    eprintln!("✗ {}: {}", path.display(), e);
                    error_count += 1;
                }
            }
        }
    } else {
        eprintln!(
            "Error: '{}' is neither a file nor a directory",
            input.display()
        );
        std::process::exit(1);
    }

    // Summary
    println!(
        "\nDone: {} file(s) unwrapped, {} error(s)",
        success_count, error_count
    );

    if error_count > 0 {
        std::process::exit(1);
    }
}
