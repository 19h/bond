//! Binary loading abstraction for ELF and PE formats

use std::path::Path;

use anyhow::{anyhow, Result};
use goblin::Object;

use super::elf::ElfLoader;
use super::pe::PeLoader;

/// CPU architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
}

/// Represents an executable code section from a binary
#[derive(Debug, Clone)]
pub struct CodeSection {
    /// Section name (e.g., ".text", ".code")
    pub name: String,
    /// Virtual address where the section is loaded
    pub virtual_address: u64,
    /// Raw bytes of the section
    pub data: Vec<u8>,
    /// Whether this section is marked as executable
    pub executable: bool,
}

/// Trait for loading binary files and extracting code sections
pub trait BinaryLoader {
    /// Get the CPU architecture of the binary
    fn architecture(&self) -> Architecture;

    /// Get all executable code sections
    fn code_sections(&self) -> Vec<CodeSection>;

    /// Get the entry point address, if available
    fn entry_point(&self) -> Option<u64>;
}

/// Load a binary file and return a loader appropriate for its format
pub fn load_binary(path: &Path) -> Result<Box<dyn BinaryLoader>> {
    let buffer = std::fs::read(path)?;
    load_binary_from_bytes(buffer)
}

/// Load a binary from raw bytes
pub fn load_binary_from_bytes(buffer: Vec<u8>) -> Result<Box<dyn BinaryLoader>> {
    match Object::parse(&buffer)? {
        Object::Elf(elf) => Ok(Box::new(ElfLoader::new(&elf, &buffer)?)),
        Object::PE(pe) => Ok(Box::new(PeLoader::new(&pe, &buffer)?)),
        Object::Mach(_) => Err(anyhow!("Mach-O binaries are not supported")),
        Object::Archive(_) => Err(anyhow!("Archive files are not supported")),
        Object::Unknown(_) => Err(anyhow!("Unknown binary format")),
        _ => Err(anyhow!("Unsupported binary format")),
    }
}
