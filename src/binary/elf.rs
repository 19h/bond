//! ELF binary parsing

use anyhow::{anyhow, Result};
use goblin::elf::{header, section_header, Elf};

use super::loader::{Architecture, BinaryLoader, CodeSection};

/// ELF binary loader
pub struct ElfLoader {
    architecture: Architecture,
    entry_point: u64,
    sections: Vec<CodeSection>,
}

impl ElfLoader {
    /// Create a new ELF loader from a parsed ELF and raw buffer
    pub fn new(elf: &Elf<'_>, buffer: &[u8]) -> Result<Self> {
        let architecture = match elf.header.e_machine {
            header::EM_386 => Architecture::X86,
            header::EM_X86_64 => Architecture::X86_64,
            machine => return Err(anyhow!("Unsupported ELF architecture: {}", machine)),
        };

        let entry_point = elf.header.e_entry;

        let sections = elf
            .section_headers
            .iter()
            .filter(|sh| {
                // Filter for executable sections with actual content
                (sh.sh_flags & section_header::SHF_EXECINSTR as u64) != 0
                    && sh.sh_type == section_header::SHT_PROGBITS
                    && sh.sh_size > 0
            })
            .filter_map(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or(".unknown");
                let start = sh.sh_offset as usize;
                let size = sh.sh_size as usize;

                // Bounds check
                if start + size > buffer.len() {
                    return None;
                }

                Some(CodeSection {
                    name: name.to_string(),
                    virtual_address: sh.sh_addr,
                    data: buffer[start..start + size].to_vec(),
                    executable: true,
                })
            })
            .collect();

        Ok(Self {
            architecture,
            entry_point,
            sections,
        })
    }
}

impl BinaryLoader for ElfLoader {
    fn architecture(&self) -> Architecture {
        self.architecture
    }

    fn code_sections(&self) -> Vec<CodeSection> {
        self.sections.clone()
    }

    fn entry_point(&self) -> Option<u64> {
        Some(self.entry_point)
    }
}
