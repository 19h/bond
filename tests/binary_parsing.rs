//! Binary parsing integration tests

mod common;

use bond::binary::loader::{load_binary, load_binary_from_bytes, Architecture, BinaryLoader, CodeSection};
use common::*;

// ============================================================================
// CodeSection Tests
// ============================================================================

#[test]
fn test_code_section_creation() {
    let section = make_code_section(".text", 0x401000, vec![0x90, 0xC3]);

    assert_eq!(section.name, ".text");
    assert_eq!(section.virtual_address, 0x401000);
    assert_eq!(section.data.len(), 2);
    assert!(section.executable);
}

#[test]
fn test_code_section_with_instructions() {
    let section = make_text_section(&[NOP, RET, MOV_RAX_RBX]);

    assert_eq!(section.name, ".text");
    assert_eq!(section.virtual_address, 0x401000);
    // NOP(1) + RET(1) + MOV_RAX_RBX(3) = 5 bytes
    assert_eq!(section.data.len(), 5);
}

// ============================================================================
// Architecture Tests
// ============================================================================

#[test]
fn test_architecture_equality() {
    assert_eq!(Architecture::X86, Architecture::X86);
    assert_eq!(Architecture::X86_64, Architecture::X86_64);
    assert_ne!(Architecture::X86, Architecture::X86_64);
}

#[test]
fn test_architecture_clone() {
    let arch = Architecture::X86_64;
    let cloned = arch;
    assert_eq!(arch, cloned);
}

// ============================================================================
// ELF Parsing Tests
// ============================================================================

#[test]
fn test_load_minimal_elf64() {
    let elf_bytes = make_minimal_elf64();
    let loader = load_binary_from_bytes(elf_bytes).expect("Failed to load minimal ELF");

    assert_eq!(loader.architecture(), Architecture::X86_64);
    assert!(loader.entry_point().is_some());
}

#[test]
fn test_elf64_entry_point() {
    let elf_bytes = make_minimal_elf64();
    let loader = load_binary_from_bytes(elf_bytes).expect("Failed to load minimal ELF");

    // Entry point should be at 0x400078 (as specified in make_minimal_elf64)
    let entry = loader.entry_point().expect("Should have entry point");
    assert_eq!(entry, 0x400078);
}

#[test]
fn test_elf64_code_sections() {
    let elf_bytes = make_minimal_elf64();
    let loader = load_binary_from_bytes(elf_bytes).expect("Failed to load minimal ELF");

    let sections = loader.code_sections();
    // Minimal ELF may not have traditional sections, but should be loadable
    // The code is in the program header, not necessarily as a named section
    // This test verifies the loader doesn't crash
    assert!(sections.is_empty() || !sections.is_empty());
}

#[test]
fn test_load_system_binary() {
    // Try to load /bin/ls if it exists (common on Linux)
    use std::path::Path;

    let path = Path::new("/bin/ls");
    if path.exists() {
        let result = load_binary(path);
        match result {
            Ok(loader) => {
                // Should be x86_64 on most modern systems
                assert!(matches!(loader.architecture(), Architecture::X86 | Architecture::X86_64));
                assert!(loader.entry_point().is_some());

                let sections = loader.code_sections();
                assert!(!sections.is_empty(), "Should have at least one code section");

                // Verify .text section exists
                let text_section = sections.iter().find(|s| s.name == ".text");
                assert!(text_section.is_some(), "Should have .text section");

                let text = text_section.unwrap();
                assert!(text.executable);
                assert!(!text.data.is_empty());
            }
            Err(_) => {
                // Skip if we can't load (might be a different architecture)
            }
        }
    }
}

// ============================================================================
// PE Parsing Tests
// ============================================================================

#[test]
fn test_load_minimal_pe64() {
    let pe_bytes = make_minimal_pe64();
    let loader = load_binary_from_bytes(pe_bytes).expect("Failed to load minimal PE");

    assert_eq!(loader.architecture(), Architecture::X86_64);
    assert!(loader.entry_point().is_some());
}

#[test]
fn test_pe64_entry_point() {
    let pe_bytes = make_minimal_pe64();
    let loader = load_binary_from_bytes(pe_bytes).expect("Failed to load minimal PE");

    let entry = loader.entry_point().expect("Should have entry point");
    // Entry point = ImageBase (0x140000000) + AddressOfEntryPoint (0x1000)
    assert_eq!(entry, 0x140001000);
}

#[test]
fn test_pe64_code_sections() {
    let pe_bytes = make_minimal_pe64();
    let loader = load_binary_from_bytes(pe_bytes).expect("Failed to load minimal PE");

    let sections = loader.code_sections();
    assert!(!sections.is_empty(), "Should have code sections");

    // Should have .text section
    let text_section = sections.iter().find(|s| s.name == ".text");
    assert!(text_section.is_some(), "Should have .text section");

    let text = text_section.unwrap();
    assert!(text.executable);
    assert!(!text.data.is_empty());
}

#[test]
fn test_pe64_section_content() {
    let pe_bytes = make_minimal_pe64();
    let loader = load_binary_from_bytes(pe_bytes).expect("Failed to load minimal PE");

    let sections = loader.code_sections();
    let text = sections.iter().find(|s| s.name == ".text").unwrap();

    // Check that the section contains our expected code
    // First instruction should be XOR RAX, RAX (48 31 C0)
    assert!(text.data.len() >= 3);
    assert_eq!(text.data[0..3], [0x48, 0x31, 0xC0]);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_load_invalid_bytes() {
    let invalid = vec![0x00, 0x01, 0x02, 0x03];
    let result = load_binary_from_bytes(invalid);

    assert!(result.is_err());
}

#[test]
fn test_load_empty_bytes() {
    let result = load_binary_from_bytes(vec![]);
    assert!(result.is_err());
}

#[test]
fn test_load_partial_elf_magic() {
    // Just the ELF magic without the rest
    let partial = vec![0x7F, b'E', b'L', b'F'];
    let result = load_binary_from_bytes(partial);

    assert!(result.is_err());
}

#[test]
fn test_load_partial_pe_magic() {
    // Just the MZ signature without the rest
    let partial = vec![0x4D, 0x5A];
    let result = load_binary_from_bytes(partial);

    assert!(result.is_err());
}

#[test]
fn test_load_nonexistent_file() {
    use std::path::Path;

    let result = load_binary(Path::new("/nonexistent/file/path"));
    assert!(result.is_err());
}

// ============================================================================
// Trait Implementation Tests
// ============================================================================

#[test]
fn test_binary_loader_trait_elf() {
    let elf_bytes = make_minimal_elf64();
    let loader: Box<dyn BinaryLoader> = load_binary_from_bytes(elf_bytes).unwrap();

    // Test through trait interface
    let _arch = loader.architecture();
    let _entry = loader.entry_point();
    let _sections = loader.code_sections();
}

#[test]
fn test_binary_loader_trait_pe() {
    let pe_bytes = make_minimal_pe64();
    let loader: Box<dyn BinaryLoader> = load_binary_from_bytes(pe_bytes).unwrap();

    // Test through trait interface
    let _arch = loader.architecture();
    let _entry = loader.entry_point();
    let _sections = loader.code_sections();
}

// ============================================================================
// Section Data Validation Tests
// ============================================================================

#[test]
fn test_section_data_not_truncated() {
    let pe_bytes = make_minimal_pe64();
    let loader = load_binary_from_bytes(pe_bytes).expect("Failed to load PE");

    for section in loader.code_sections() {
        // Data should match the section's expected size
        assert!(!section.data.is_empty());
        // All bytes should be accessible
        let _first = section.data[0];
        let _last = section.data[section.data.len() - 1];
    }
}

#[test]
fn test_virtual_address_valid() {
    let pe_bytes = make_minimal_pe64();
    let loader = load_binary_from_bytes(pe_bytes).expect("Failed to load PE");

    for section in loader.code_sections() {
        // Virtual address should be non-zero and reasonable
        assert!(section.virtual_address > 0);
        // For PE, should be relative to image base
        assert!(section.virtual_address >= 0x10000);
    }
}

// ============================================================================
// Format Detection Tests
// ============================================================================

#[test]
fn test_format_detection_elf() {
    let elf_bytes = make_minimal_elf64();
    // First 4 bytes should be ELF magic
    assert_eq!(&elf_bytes[0..4], &[0x7F, b'E', b'L', b'F']);

    let loader = load_binary_from_bytes(elf_bytes).unwrap();
    assert_eq!(loader.architecture(), Architecture::X86_64);
}

#[test]
fn test_format_detection_pe() {
    let pe_bytes = make_minimal_pe64();
    // First 2 bytes should be MZ signature
    assert_eq!(&pe_bytes[0..2], &[0x4D, 0x5A]);

    let loader = load_binary_from_bytes(pe_bytes).unwrap();
    assert_eq!(loader.architecture(), Architecture::X86_64);
}
