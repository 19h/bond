//! PE binary parsing

use anyhow::{anyhow, Result};
use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;
use goblin::pe::PE;

use super::loader::{Architecture, BinaryLoader, CodeSection};

/// PE binary loader
pub struct PeLoader {
    architecture: Architecture,
    entry_point: u64,
    sections: Vec<CodeSection>,
}

impl PeLoader {
    /// Create a new PE loader from a parsed PE and raw buffer
    pub fn new(pe: &PE<'_>, buffer: &[u8]) -> Result<Self> {
        let architecture = if pe.is_64 {
            Architecture::X86_64
        } else {
            Architecture::X86
        };

        let image_base = pe.image_base as u64;
        let entry_point = image_base + pe.entry as u64;

        let sections: Vec<CodeSection> = pe
            .sections
            .iter()
            .filter(|section| {
                // Filter for executable sections with actual content
                (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                    && section.size_of_raw_data > 0
            })
            .filter_map(|section| {
                // Get section name, trimming null bytes
                let name = String::from_utf8_lossy(&section.name)
                    .trim_end_matches('\0')
                    .to_string();

                let start = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;

                // Bounds check
                if start + size > buffer.len() {
                    return None;
                }

                Some(CodeSection {
                    name,
                    virtual_address: image_base + section.virtual_address as u64,
                    data: buffer[start..start + size].to_vec(),
                    executable: true,
                })
            })
            .collect();

        if sections.is_empty() {
            return Err(anyhow!("No executable sections found in PE"));
        }

        Ok(Self {
            architecture,
            entry_point,
            sections,
        })
    }
}

impl BinaryLoader for PeLoader {
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
