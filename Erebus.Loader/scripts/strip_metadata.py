#!/usr/bin/env python3
"""
Strip forensic metadata from compiled PE files.

Removes:
  - Rich header (compiler fingerprint between DOS stub and PE signature)
  - PE timestamp (TimeDateStamp in COFF header)
  - Debug directory entries (PDB paths)

Usage: python3 strip_metadata.py <pe_file>
"""

import struct
import sys
from pathlib import Path


def strip_rich_header(data: bytearray) -> bytearray:
    """Zero out the Rich header between the DOS stub and PE signature."""
    # Find "Rich" signature (marks the end of the Rich header)
    rich_offset = data.find(b'Rich')
    if rich_offset == -1:
        return data

    # The XOR key is the 4 bytes after "Rich"
    # The Rich header starts after the DOS stub (typically offset 0x80)
    # and extends to "Rich" + 8 bytes (key)
    dos_stub_end = 0x80  # Standard DOS stub size

    # Find the actual start by looking for the "DanS" marker (XORed)
    key = struct.unpack_from('<I', data, rich_offset + 4)[0]
    dans_marker = struct.pack('<I', 0x536E6144 ^ key)  # "DanS" XORed

    dans_offset = data.find(dans_marker, dos_stub_end)
    if dans_offset == -1:
        dans_offset = dos_stub_end

    # Zero the entire Rich header region
    rich_end = rich_offset + 8  # "Rich" + 4-byte key
    for i in range(dans_offset, rich_end):
        data[i] = 0x00

    return data


def zero_timestamp(data: bytearray) -> bytearray:
    """Zero the PE TimeDateStamp in the COFF header."""
    # PE signature offset is at DOS header offset 0x3C
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]

    # Verify PE signature
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        return data

    # TimeDateStamp is at PE offset + 8 (COFF header, 4 bytes after Machine)
    ts_offset = pe_offset + 8
    struct.pack_into('<I', data, ts_offset, 0)

    return data


def strip_debug_directory(data: bytearray) -> bytearray:
    """Zero out debug directory entries (removes PDB paths)."""
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        return data

    # Optional header starts at PE + 24
    opt_offset = pe_offset + 24
    magic = struct.unpack_from('<H', data, opt_offset)[0]

    # Debug directory is index 6 in the data directory array
    if magic == 0x20B:  # PE32+
        dd_offset = opt_offset + 112 + (6 * 8)  # 112 = fixed optional header fields for PE32+
    elif magic == 0x10B:  # PE32
        dd_offset = opt_offset + 96 + (6 * 8)
    else:
        return data

    debug_rva = struct.unpack_from('<I', data, dd_offset)[0]
    debug_size = struct.unpack_from('<I', data, dd_offset + 4)[0]

    if debug_rva == 0 or debug_size == 0:
        return data

    # Zero the data directory entry itself
    struct.pack_into('<I', data, dd_offset, 0)
    struct.pack_into('<I', data, dd_offset + 4, 0)

    return data


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pe_file>", file=sys.stderr)
        sys.exit(1)

    pe_path = Path(sys.argv[1])
    if not pe_path.exists():
        print(f"File not found: {pe_path}", file=sys.stderr)
        sys.exit(1)

    data = bytearray(pe_path.read_bytes())

    # Verify MZ signature
    if data[:2] != b'MZ':
        print(f"Not a PE file: {pe_path}", file=sys.stderr)
        sys.exit(1)

    data = strip_rich_header(data)
    data = zero_timestamp(data)
    data = strip_debug_directory(data)

    pe_path.write_bytes(data)
    print(f"Stripped metadata from {pe_path.name}")


if __name__ == '__main__':
    main()
