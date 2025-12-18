#!/bin/bash
# Build script for Bond training corpus and test binaries
# This script compiles all C source files into ELF binaries for testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
BIN_DIR="$SCRIPT_DIR/bin"

# Create bin directory if it doesn't exist
mkdir -p "$BIN_DIR"

# Compiler settings
CC="${CC:-gcc}"
CFLAGS="-O2 -fno-inline-functions -fno-omit-frame-pointer"
CFLAGS_DEBUG="-O0 -g -fno-inline-functions -fno-omit-frame-pointer"

echo "=== Bond Corpus Build Script ==="
echo "Compiler: $CC"
echo "Source directory: $SRC_DIR"
echo "Output directory: $BIN_DIR"
echo ""

# Function to compile a source file
compile_file() {
    local src="$1"
    local name=$(basename "$src" .c)
    local out="$BIN_DIR/$name"

    echo "Compiling $name..."

    # Compile optimized version (for pattern detection)
    $CC $CFLAGS -o "${out}" "$src"
    echo "  -> ${out}"

    # Compile debug version (for debugging)
    $CC $CFLAGS_DEBUG -o "${out}_debug" "$src"
    echo "  -> ${out}_debug"

    # Strip symbols from optimized version for realistic testing
    strip -s "${out}" -o "${out}_stripped"
    echo "  -> ${out}_stripped"
}

# Check if GCC is available
if ! command -v $CC &> /dev/null; then
    echo "Error: Compiler '$CC' not found"
    echo "Please install GCC or set CC environment variable"
    exit 1
fi

# Compile training corpus
echo ""
echo "=== Building Training Corpus ==="
for src in "$SRC_DIR"/train_*.c; do
    if [ -f "$src" ]; then
        compile_file "$src"
    fi
done

# Compile test binaries
echo ""
echo "=== Building Test Binaries ==="
for src in "$SRC_DIR"/test_*.c; do
    if [ -f "$src" ]; then
        compile_file "$src"
    fi
done

# Generate a manifest file
echo ""
echo "=== Generating Manifest ==="
MANIFEST="$BIN_DIR/manifest.txt"
echo "# Bond Corpus Manifest" > "$MANIFEST"
echo "# Generated: $(date)" >> "$MANIFEST"
echo "" >> "$MANIFEST"

echo "# Training binaries (for HTM learning)" >> "$MANIFEST"
for bin in "$BIN_DIR"/train_*; do
    if [ -f "$bin" ] && [[ ! "$bin" == *_debug ]] && [[ ! "$bin" == *_stripped ]]; then
        echo "$bin" >> "$MANIFEST"
    fi
done

echo "" >> "$MANIFEST"
echo "# Test binaries (for pattern detection)" >> "$MANIFEST"
for bin in "$BIN_DIR"/test_*; do
    if [ -f "$bin" ] && [[ ! "$bin" == *_debug ]] && [[ ! "$bin" == *_stripped ]]; then
        echo "$bin" >> "$MANIFEST"
    fi
done

echo "Manifest written to: $MANIFEST"

# Summary
echo ""
echo "=== Build Complete ==="
echo "Training binaries:"
ls -la "$BIN_DIR"/train_* 2>/dev/null | grep -v "_debug\|_stripped" || echo "  (none)"
echo ""
echo "Test binaries:"
ls -la "$BIN_DIR"/test_* 2>/dev/null | grep -v "_debug\|_stripped" || echo "  (none)"
echo ""
echo "Total files: $(ls -1 "$BIN_DIR"/*.txt "$BIN_DIR"/train_* "$BIN_DIR"/test_* 2>/dev/null | wc -l)"
