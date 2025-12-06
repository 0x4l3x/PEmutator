#!/usr/bin/env python3
"""
PEmutator: Unified Tool for PE Mutation and Mass Variant Generation

This script supports both single-file mutation and bulk processing of PE files
with consistent, documented, and reproducible modifications.
"""

import os
import sys
import random
import string
import hashlib
import argparse
import struct
import shutil
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from random import randint
from magika import Magika
import lief
import pefile
import pyzipper

# === CONFIGURATION ===

BENIGN_IMPORTS = {
    "kernel32.dll": ["GetCurrentThreadId", "GetTickCount", "GetSystemTime"],
    "user32.dll": ["GetForegroundWindow", "MessageBoxA"],
    "advapi32.dll": ["GetUserNameA"]
}

PROTECTED_SECTIONS = [b".text", b".rdata", b".rsrc", b".edata", b".idata", b".reloc"]


# === HELPER FUNCTIONS ===

def hash_file(filepath: str, algo: str = 'sha256') -> str:
    h = hashlib.new(algo)
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def read_pe_header_offsets(data: bytes):
    if data[:2] != b"MZ":
        raise ValueError("Not a DOS/PE file")
    pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
    if data[pe_offset:pe_offset+4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    return pe_offset


def generate_timestamp_from_date(date_str: str) -> int:
    """Converts DD/MM/YYYY to a timestamp with randomized time (08:00-18:00)."""
    try:
        dt_object = datetime.strptime(date_str, '%d/%m/%Y')
        random_hour = randint(8, 18)
        random_minute = randint(0, 59)
        random_second = randint(0, 59)
        dt_object_with_time = dt_object.replace(
            hour=random_hour, minute=random_minute, second=random_second
        )
        return int(dt_object_with_time.timestamp())
    except ValueError:
        print(f"[!] Invalid date format: {date_str}. Use DD/MM/YYYY.")
        sys.exit(1)


def generate_random_timestamp() -> int:
    """Generates a random timestamp between 2015 and 2024."""
    # 2015-01-01 to ~End of 2024
    return randint(1420070400, 1735689599)


# === RAW PATCHING (SAFE MODE) ===

def patch_timestamp_in_place(target_path: str, new_ts: int, verbose: bool = False):
    try:
        with open(target_path, "r+b") as f:
            data = f.read()
            pe_offset = read_pe_header_offsets(data)
            timestamp_offset = pe_offset + 8
            old_ts = struct.unpack("<I", data[timestamp_offset:timestamp_offset+4])[0]
            f.seek(timestamp_offset)
            f.write(struct.pack("<I", new_ts))
        
        if verbose:
            old_dt = datetime.fromtimestamp(old_ts, tz=timezone.utc) if old_ts else "0"
            new_dt = datetime.fromtimestamp(new_ts, tz=timezone.utc)
            print(f"[VERBOSE] Timestamp: {old_dt} -> {new_dt}")
        return True
    except Exception as e:
        if verbose:
            print(f"[VERBOSE] Timestamp patch failed: {e}")
        return False


def patch_section_names(target_path: str, verbose: bool = False):
    try:
        with open(target_path, "r+b") as f:
            data = f.read()
            pe_offset = read_pe_header_offsets(data)
            coff_start = pe_offset + 4
            size_opt_header = struct.unpack("<H", data[coff_start+16:coff_start+18])[0]
            num_sections = struct.unpack("<H", data[coff_start+2:coff_start+4])[0]
            section_table_offset = coff_start + 20 + size_opt_header
            
            current_offset = section_table_offset
            modified = False
            
            for _ in range(num_sections):
                name = data[current_offset:current_offset+8].rstrip(b"\x00")
                if name not in PROTECTED_SECTIONS:
                    new_name = b"." + "".join(random.choices(string.ascii_lowercase, k=5)).encode()
                    new_name = new_name.ljust(8, b"\x00")[:8]
                    f.seek(current_offset)
                    f.write(new_name)
                    if verbose:
                        print(f"[VERBOSE] Renamed section {name} -> {new_name.rstrip(b' ')}")
                    modified = True
                current_offset += 40
        return modified
    except Exception as e:
        if verbose:
            print(f"[VERBOSE] Section rename failed: {e}")
        return False


def append_overlay(target_path: str, verbose: bool = False):
    try:
        overlay_size = random.randint(64, 512)
        junk = os.urandom(overlay_size)
        with open(target_path, "ab") as f:
            f.write(junk)
        if verbose:
            print(f"[VERBOSE] Appended {overlay_size}-byte overlay")
        return True
    except Exception as e:
        if verbose:
            print(f"[VERBOSE] Overlay append failed: {e}")
        return False


# === LIEF MODIFICATIONS (AGGRESSIVE MODE) ===

def apply_lief_modifications(args, input_path: str, output_path: str):
    binary = lief.PE.parse(input_path)
    modifications = []

    # 1. Import Manipulation
    if args.imphash or args.aggressive:
        dll = random.choice(list(BENIGN_IMPORTS.keys()))
        func = random.choice(BENIGN_IMPORTS[dll])
        
        # Check if library already exists
        lib = next((l for l in binary.imports if l.name.lower() == dll.lower()), None)
        if not lib:
            lib = binary.add_library(dll)
        
        if not any(e.name == func for e in lib.entries):
            lib.add_entry(func)
            modifications.append(f"Added import {dll}!{func}")

    # 2. Add Junk Section
    if args.junk_section or args.aggressive:
        random_suffix = "".join(random.choices(string.ascii_lowercase, k=4))
        name = f".{random_suffix}"
        size = random.randint(100, 500)
        section = lief.PE.Section(name)
        section.content = [random.randint(0,255) for _ in range(size)]
        section.characteristics = (
            lief.PE.Section.CHARACTERISTICS.MEM_READ |
            lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA
        )
        binary.add_section(section)
        modifications.append(f"Added junk section {name}")

    # 3. Disable ASLR
    if args.disable_aslr or args.aggressive:
        if binary.optional_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE):
            binary.optional_header.remove(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE)
            modifications.append("Disabled ASLR")

    # 4. Modify Flags (Mark sections as readable)
    if args.modify_flags or args.aggressive:
        for sec in binary.sections:
            name = sec.name.rstrip("\x00")
            # Don't mess with text or protected sections too much to avoid breakage
            if name.encode() not in PROTECTED_SECTIONS and "text" not in name.lower():
                if not sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ):
                    sec.add_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ)
                    modifications.append(f"Added MEM_READ to {name}")

    # Rebuild
    builder = lief.PE.Builder(binary)
    builder.build_imports(True)
    builder.build_resources(True)
    builder.build()
    builder.write(output_path)
    return modifications


# === BULK-ONLY UTILITIES ===

def get_pe_info(filepath: str) -> dict:
    try:
        pe = pefile.PE(filepath)
        sections = [sec.Name.decode(errors='ignore').rstrip('\x00') for sec in pe.sections]
        pe.close()
        return {"original_hash": hash_file(filepath), "sections": sections}
    except Exception as e:
        return {"original_hash": hash_file(filepath), "sections": [f"(Parse error: {e})"]}

def create_compressed_archive_multiple(file_paths, zip_path, password: str = "infected"):
    """Create an AES-256 encrypted ZIP archive containing multiple files."""
    with pyzipper.AESZipFile(zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode('utf-8'))
        for fp in file_paths:
            zf.write(fp, arcname=os.path.basename(fp))

def generate_markdown_report(report_data: dict, output_file: str):
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Bulk PE Modification Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Mode:** {report_data['config']['mode'].upper()}\n")
        f.write(f"**Base Date:** {report_data['config']['base_date']}\n")
        f.write(f"**Variants per file:** {report_data['config']['variants']}\n\n")
        f.write("## Summary\n\n")
        f.write(f"- **Total input files:** {len(report_data['files'])}\n")
        f.write(f"- **Total variants generated:** {sum(len(data['variants']) for data in report_data['files'].values())}\n")
        f.write(f"- **Success rate:** {report_data['stats']['success_rate']:.1f}%\n\n")
        f.write("## File Details\n\n")
        for input_file, file_data in report_data['files'].items():
            f.write(f"### {os.path.basename(input_file)}\n\n")
            f.write(f"- **Original Hash:** `{file_data['original_info']['original_hash']}`\n")
            f.write(f"- **Sections:** {', '.join(file_data['original_info'].get('sections', ['Unknown']))}\n")
            f.write(f"- **Variants generated:** {len(file_data['variants'])}\n\n")
            f.write("#### Variants\n\n")
            f.write("| Variant | Output File | New Hash | Modifications | Status |\n")
            f.write("|---------|-------------|----------|---------------|--------|\n")
            for variant in file_data['variants']:
                status = "✅ Success" if variant['success'] else "❌ Failed"
                mods_count = len(variant['modifications'])
                f.write(f"| {variant['variant_number']:02d} | `{os.path.basename(variant['output_file'])}` | ")
                f.write(f"`{variant['new_hash']}` | {mods_count} mods | {status} |\n")
            f.write("\n")


# === CORE MUTATOR ===

def mutate_pe_file(args, modifications_out=None):
    """Core logic to mutate a single PE file."""
    if not os.path.isfile(args.input):
        print(f"[!] Input not found: {args.input}")
        sys.exit(1)

    # Determine if LIEF is needed
    specific_lief_requested = any([args.imphash, args.junk_section, args.disable_aslr, args.modify_flags])
    should_run_lief = False

    if args.aggressive:
        should_run_lief = True
    elif args.safe:
        should_run_lief = False
        if specific_lief_requested:
            print("[!] WARNING: --safe mode is on. Ignoring LIEF-dependent flags.")
    else:
        should_run_lief = specific_lief_requested

    modifications = []

    # Phase 1: Structural Modifications (LIEF) or Copy
    if should_run_lief:
        print("[*] Phase 1: Applying structural LIEF modifications...")
        try:
            modifications.extend(apply_lief_modifications(args, args.input, args.output))
        except Exception as e:
            # Fallback to copy if LIEF fails, to allow raw patching to attempt
            print(f"[!] LIEF Failed: {e}. Falling back to raw copy.")
            shutil.copy2(args.input, args.output)
            modifications.append("LIEF failed (fallback to original)")
    else:
        print("[*] Phase 1: Copying base file (Safe Mode)...")
        shutil.copy2(args.input, args.output)

    # Phase 2: Raw patching on output file
    
    # 2a. Section Renaming
    if args.rename_sections or args.aggressive or args.safe:
        if patch_section_names(args.output, args.verbose):
            modifications.append("Section names randomized (Raw Patch)")

    # 2b. Timestamp Modification
    # Calculate the timestamp integer
    final_ts = None
    if getattr(args, 'set_date', None):
        final_ts = generate_timestamp_from_date(args.set_date)
    elif getattr(args, 'random_date', False):
        final_ts = generate_random_timestamp()
    elif getattr(args, 'forced_timestamp_val', None):
        # Used by Bulk mode to force a specific integer
        final_ts = args.forced_timestamp_val
    else:
        # Default behavior if flags not set but safe/aggressive mode is
        if args.aggressive or args.safe:
            final_ts = generate_random_timestamp()

    if final_ts:
        if patch_timestamp_in_place(args.output, final_ts, args.verbose):
            dt = datetime.fromtimestamp(final_ts, tz=timezone.utc)
            modifications.append(f"Timestamp set to {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # 2c. Overlay
    if args.overlay or args.aggressive or args.safe:
        if append_overlay(args.output, args.verbose):
            modifications.append("Random overlay appended")

    # Final Verification
    new_hash = hash_file(args.output)
    
    # Optional Validation
    if args.validate:
        try:
            _ = lief.PE.parse(args.output)
            if args.verbose:
                print("[+] Output validates as PE")
        except Exception as e:
            print(f"[!] Validation failed: {e}")
            modifications.append(f"Validation Failed: {e}")

    if modifications_out is not None:
        modifications_out.extend(modifications)
    
    # Console output for Single mode
    if getattr(args, 'command', '') == 'single':
        print(f"\n[+] Applied {len(modifications)} modification(s):")
        for m in modifications:
            print(f"    • {m}")
        print(f"\n[+] SUCCESS -> {new_hash}")

    return new_hash


# === MODE HANDLERS ===

def handle_single_mode(args):
    mutate_pe_file(args)

def handle_bulk_mode(args):
    if not os.path.exists(args.input):
        print(f"[!] Input folder not found: {args.input}")
        sys.exit(1)
    if args.variants < 1:
        print("[!] Number of variants must be at least 1")
        sys.exit(1)

    args.input = os.path.abspath(args.input)
    args.output = os.path.abspath(args.output)

    output_dir = Path(args.output)
    compressed_dir = Path(f"{args.output}_compressed")
    output_dir.mkdir(parents=True, exist_ok=True)
    compressed_dir.mkdir(parents=True, exist_ok=True)

    # Identify PE files using Magika
    magika_model = Magika()
    pe_files = []
    print("[*] Scanning for PE files using Magika...")
    for file_path in Path(args.input).iterdir():
        if file_path.is_file():
            try:
                result = magika_model.identify_path(file_path)
                if result.output.ct_label.startswith('pe'):
                    pe_files.append(file_path)
            except Exception as e:
                print(f"[!] Magika error on {file_path.name}: {e}")

    if not pe_files:
        print(f"[!] No PE files found in {args.input}")
        sys.exit(1)

    print(f"[*] Found {len(pe_files)} PE file(s). Generating {args.variants} variant(s) each.")
    print(f"[*] Output: {output_dir}")
    print(f"[*] Base Date: {args.date}")
    
    # Calculate base timestamp for this batch
    base_ts = generate_timestamp_from_date(args.date)

    report_data = {
        'config': {
            'base_date': args.date,
            'mode': args.mode,
            'variants': args.variants,
            'validate': args.validate
        },
        'files': {},
        'stats': {'total_variants': 0, 'successful_variants': 0, 'failed_variants': 0}
    }

    variant_groups = {i: [] for i in range(1, args.variants + 1)}

    for pe_file in pe_files:
        print(f"\n[*] Processing: {pe_file.name}")
        original_info = get_pe_info(str(pe_file))
        file_variants = []
        report_data['files'][str(pe_file)] = {'original_info': original_info, 'variants': file_variants}

        for i in range(1, args.variants + 1):
            variant_num = f"{i:02d}"
            output_filename = f"{pe_file.stem}_{variant_num}{pe_file.suffix}"
            output_path = output_dir / output_filename

            # Map bulk args to single-mode args structure
            inner_args = argparse.Namespace(
                command='bulk',
                input=str(pe_file),
                output=str(output_path),
                verbose=args.verbose,
                validate=args.validate,
                
                # Mode Flags
                safe=(args.mode == 'safe'),
                aggressive=(args.mode == 'aggressive'),
                
                # Timestamp (Passed as pre-calculated int)
                forced_timestamp_val=base_ts,
                set_date=None,
                random_date=False,

                # Detailed Flags (enabled based on mode)
                rename_sections=True,
                modify_flags=(args.mode == 'aggressive'),
                imphash=(args.mode == 'aggressive'),
                junk_section=(args.mode == 'aggressive'),
                overlay=True,
                disable_aslr=(args.mode == 'aggressive')
            )

            modifications_out = []
            try:
                new_hash = mutate_pe_file(inner_args, modifications_out)
                success = True
            except Exception as e:
                success = False
                new_hash = "N/A"
                modifications_out.append(f"Execution Exception: {e}")
                if args.verbose:
                    print(f"    [!] Failed: {e}")

            variant_data = {
                'variant_number': i,
                'output_file': str(output_path),
                'new_hash': new_hash,
                'modifications': modifications_out,
                'success': success,
            }
            file_variants.append(variant_data)

            report_data['stats']['total_variants'] += 1
            if success:
                report_data['stats']['successful_variants'] += 1
                status = "✅"
                variant_groups[i].append(str(output_path))
            else:
                report_data['stats']['failed_variants'] += 1
                status = "❌"

            if args.verbose:
                print(f"    {status} Var {variant_num}: {len(modifications_out)} mods")

    # Compression Phase
    print("\n[*] creating grouped ZIP archives...")
    for idx in range(1, args.variants + 1):
        variant_files = variant_groups[idx]
        if variant_files:
            zip_name = f"{Path(args.input).name}_variant_{idx:02d}.zip"
            zip_path = compressed_dir / zip_name
            try:
                create_compressed_archive_multiple(variant_files, str(zip_path))
                print(f"    [+] Created: {zip_path.name}")
            except Exception as e:
                print(f"    [!] Failed to zip {zip_name}: {e}")

    # Report Phase
    success_rate = (report_data['stats']['successful_variants'] / report_data['stats']['total_variants'] * 100) if report_data['stats']['total_variants'] > 0 else 0
    report_data['stats']['success_rate'] = success_rate
    report_file = compressed_dir / "processing_report.md"
    generate_markdown_report(report_data, str(report_file))

    print("\n[+] BULK PROCESSING COMPLETE")
    print(f"    Report saved to: {report_file}")


def main():
    parser = argparse.ArgumentParser(description="PEmutator: Advanced PE Modification Tool")
    subparsers = parser.add_subparsers(dest='command', required=True, help='Operation mode')

    # --- Single-file mode ---
    single_parser = subparsers.add_parser('single', help='Mutate a single PE file')
    single_parser.add_argument('-i', '--input', required=True, help="Input PE file")
    single_parser.add_argument('-o', '--output', required=True, help="Output PE file")
    
    # Timestamp Group
    ts_group = single_parser.add_mutually_exclusive_group()
    ts_group.add_argument('--set-date', type=str, help="Set specific compilation date (DD/MM/YYYY)")
    ts_group.add_argument('--random-date', action='store_true', help="Set a random date (2015-2024)")

    # Mode Group
    mode_group = single_parser.add_mutually_exclusive_group()
    mode_group.add_argument('--safe', action='store_true', help="Only use raw patching (Overlay, Rename Sections, Timestamp)")
    mode_group.add_argument('--aggressive', action='store_true', help="Use LIEF for structural changes (Imports, Sections, ASLR)")
    
    # Granular Controls
    group = single_parser.add_argument_group('Granular Controls')
    group.add_argument('--rename-sections', action='store_true')
    group.add_argument('--modify-flags', action='store_true')
    group.add_argument('--imphash', action='store_true')
    group.add_argument('--junk-section', action='store_true')
    group.add_argument('--overlay', action='store_true')
    group.add_argument('--disable-aslr', action='store_true')
    
    # General
    single_parser.add_argument('--verbose', '-v', action='store_true')
    single_parser.add_argument('--validate', action='store_true', help="Validate PE structure after mutation")

    # --- Bulk mode ---
    bulk_parser = subparsers.add_parser('bulk', help='Process multiple PE files in bulk')
    bulk_parser.add_argument('-i', '--input', required=True, help='Input folder containing PE files')
    bulk_parser.add_argument('-n', '--variants', type=int, required=True, help='Number of variants per file')
    bulk_parser.add_argument('-d', '--date', type=str, required=True, help='Base compilation date (DD/MM/YYYY)')
    bulk_parser.add_argument('-o', '--output', required=True, help='Output folder')
    bulk_parser.add_argument('-m', '--mode', choices=['safe', 'aggressive'], default="safe", help="Mutation intensity")
    bulk_parser.add_argument('--validate', action='store_true')
    bulk_parser.add_argument('--verbose', action='store_true')

    args = parser.parse_args()
    print("\n=== PEmutator v1.0 ===\n")

    if args.command == 'single':
        handle_single_mode(args)
    elif args.command == 'bulk':
        handle_bulk_mode(args)

if __name__ == '__main__':
    main()