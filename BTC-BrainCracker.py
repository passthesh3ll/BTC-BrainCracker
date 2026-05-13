#!/usr/bin/env python3
"""BTC BrainCracker — Recursively scans wordlists/*.{dic,txt,zst,gz} or wallet files against local DB.
Generates both Compressed [C] and Uncompressed [U] addresses.
Requires: pip install colorama ecdsa pycryptodome base58 zstandard tqdm pyfiglet"""

import argparse
import base64
import base58
import gzip
import hashlib
import os
import sys
from pathlib import Path
from typing import List, Tuple, Optional

import zstandard
from colorama import init, Fore, Style
from Crypto.Hash import RIPEMD160, SHA256
from ecdsa import SigningKey, SECP256k1
from tqdm import tqdm

init(autoreset=True)

# Configuration constants
RESUME_DIR = Path("resume")
LOCAL_DB_PATH = Path("./funded/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz")


def print_banner():
    """Print ASCII art banner with 'BTC BrainCracker' in orange."""
    try:
        from pyfiglet import Figlet
        f = Figlet(font='smslant')
        ascii_art = f.renderText("BTC BrainCracker")
        lines = [r.rstrip() for r in ascii_art.splitlines()]
        for line in lines:
            print(f"{Fore.LIGHTYELLOW_EX}{line}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTYELLOW_EX}by @passthesh3ll{Style.RESET_ALL}")
    except ImportError:
        print(f"{Fore.LIGHTYELLOW_EX}BTC BrainCracker{Style.RESET_ALL}")
    print()


def parse_args():
    """Parse command line arguments."""
    p = argparse.ArgumentParser(
        description="BTC BrainCracker - Local DB Mode Only",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("-i", "--input", required=True, help="Input file or directory")
    p.add_argument("-o", "--output", required=True, help="Output file")
    p.add_argument("--mode", required=True, choices=["wallet", "cuser", "cpass", "wordlist"], 
                   help="wordlist:  Standard list of words (<word> format, one word per line)\n"
                        "cuser:     Extract usernames from combolists (<user:pass> format, taking the field before \":\" and removing @domain)\n"
                        "cpass:     Extract passwords from combolists (<user:pass> format, taking the field after \":\")\n"
                        "wallet:    Check existing wallet credentials (<privatekey;address> format)")
    p.add_argument("--lowcase", action="store_true", help="Force lowercase for key generation")
    return p.parse_args()


def get_resume_path(input_path: Path) -> Path:
    """Generate resume file path."""
    b64 = base64.urlsafe_b64encode(str(input_path.absolute()).encode()).decode()
    return RESUME_DIR / f"{b64}.resume"


def load_resume(resume_path: Path) -> Tuple[str, int]:
    """Load last checkpoint."""
    if not resume_path.exists():
        return "", 0
    try:
        with open(resume_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        if ':' in content:
            path_part, line_part = content.rsplit(':', 1)
            return path_part, int(line_part)
        return content, 0
    except Exception:
        return "", 0


def save_resume(resume_path: Path, rel_path: str, line_no: int):
    """Save checkpoint to resume file. Use -1 for completed files."""
    resume_path.parent.mkdir(parents=True, exist_ok=True)
    with open(resume_path, 'w', encoding='utf-8') as f:
        f.write(f"{rel_path}:{line_no}")


def count_lines_fast(file_path: Path) -> int:
    """Count lines efficiently for various compression formats."""
    try:
        suffix = file_path.suffix.lower()
        if suffix == '.zst':
            with zstandard.open(file_path, "rt", encoding="utf-8", errors="ignore") as f:
                return sum(1 for _ in f)
        elif suffix == '.gz':
            with gzip.open(file_path, "rt", encoding="utf-8", errors="ignore") as f:
                return sum(1 for _ in f)
        else:
            count = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    count += chunk.count(b'\n')
            return count
    except Exception:
        return 0


def truncate_filename(name: str, max_len: int = 25) -> str:
    """Truncate filename keeping extension with [..] notation."""
    if len(name) <= max_len:
        return name
    
    if '.' in name:
        dot_idx = name.rfind('.')
        ext = name[dot_idx:]
        base = name[:dot_idx]
        suffix = "[..]"
        available = max_len - len(suffix) - len(ext)
        if available >= 3:
            return base[:available] + suffix + ext
        else:
            return name[:max_len-4] + "[..]"
    else:
        return name[:max_len-4] + "[..]"


def extract_word(line: str, mode: str) -> Optional[str]:
    """Extract word from line based on operation mode."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    if mode == "wordlist":
        return line.split('/')[0].strip()
    
    if ':' not in line:
        return None
    
    user, passwd = line.split(':', 1)
    if mode == "cuser":
        return user.strip().split('@')[0]
    return passwd.strip()


def normalize_priv_to_wif(priv_raw: str) -> Optional[str]:
    """Convert various private key formats to WIF (compressed)."""
    priv_raw = priv_raw.strip()
    if not priv_raw:
        return None
    try:
        if len(priv_raw) == 64:
            priv_bytes = bytes.fromhex(priv_raw)
        elif len(priv_raw) == 32:
            priv_bytes = priv_raw.encode('latin-1') if isinstance(priv_raw, str) else priv_raw
        else:
            return None
        ext = b'\x80' + priv_bytes + b'\x01'
        checksum = hashlib.sha256(hashlib.sha256(ext).digest()).digest()[:4]
        return base58.b58encode(ext + checksum).decode('ascii')
    except Exception:
        return None


def parse_wallet_line(line: str) -> Optional[Tuple[str, str, List[str]]]:
    """Parse wallet line."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    parts = line.split(';')
    if len(parts) == 2:
        return parts[0], parts[1], parts
    if len(parts) >= 3:
        return parts[1], parts[2], parts
    return None


def build_output_line(priv: str, addr: str, bal: str, date: str, last: str, word: str) -> str:
    """Construct output line."""
    return f"{priv};{addr};{bal};{date};{last};{word}"


def sat_to_btc(sat: int) -> float:
    """Convert satoshis to BTC."""
    return sat / 100_000_000.0


def generate_key_pairs_sync(word: str, lowcase: bool = False):
    """Synchronous key generation."""
    w = word.strip()
    if not w:
        return []
    if lowcase:
        w = w.lower()
    
    priv_bytes = hashlib.sha256(w.encode('utf-8')).digest()
    
    try:
        sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        x_bytes = x.to_bytes(32, 'big')
        y_bytes = y.to_bytes(32, 'big')
        
        results = []
        
        # Compressed
        prefix = b'\x02' if (y % 2 == 0) else b'\x03'
        pub_compressed = prefix + x_bytes
        addr_compressed = pubkey_to_address(pub_compressed)
        wif_compressed = priv_to_wif(priv_bytes, compressed=True)
        results.append((wif_compressed, addr_compressed, True))
        
        # Uncompressed
        pub_uncompressed = b'\x04' + x_bytes + y_bytes
        addr_uncompressed = pubkey_to_address(pub_uncompressed)
        wif_uncompressed = priv_to_wif(priv_bytes, compressed=False)
        results.append((wif_uncompressed, addr_uncompressed, False))
        
        return results
    except Exception:
        return []


def pubkey_to_address(pub_key_bytes: bytes) -> str:
    """Convert public key bytes to Bitcoin P2PKH address."""
    sha256_pub = SHA256.new(pub_key_bytes).digest()
    hash160 = RIPEMD160.new(sha256_pub).digest()
    versioned = b'\x00' + hash160
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58.b58encode(versioned + checksum).decode('ascii')


def priv_to_wif(priv_bytes: bytes, compressed: bool = False) -> str:
    """Convert private key bytes to WIF."""
    if compressed:
        ext = b'\x80' + priv_bytes + b'\x01'
    else:
        ext = b'\x80' + priv_bytes
    checksum = hashlib.sha256(hashlib.sha256(ext).digest()).digest()[:4]
    return base58.b58encode(ext + checksum).decode('ascii')


def format_output_line(first_col: str, addr: str, is_compressed: Optional[bool], bal_str: str, last_str: str):
    """Format terminal output line."""
    if is_compressed is None:
        return f"{first_col} | {Fore.CYAN}{addr}{Style.RESET_ALL} | Balance: {bal_str} | Last: {last_str}"
    marker = f"{Fore.LIGHTYELLOW_EX}[{'C' if is_compressed else 'U'}]{Style.RESET_ALL}"
    return f"{first_col} | {marker} {Fore.CYAN}{addr}{Style.RESET_ALL} | Balance: {bal_str} | Last: {last_str}"


def scan_file(file_path: Path, rel_path: str, mode: str, lowcase: bool,
              local_db: dict, output_file: str, seen_addrs: set,
              start_line: int, resume_path: Path, pbar: tqdm):
    """Scan file with LocalDB - single threaded."""
    opener = lambda p, m: (
        zstandard.open(p, m, encoding="utf-8", errors="ignore") if p.suffix.lower() == '.zst' 
        else gzip.open(p, m, encoding="utf-8", errors="ignore") if p.suffix.lower() == '.gz'
        else open(p, m, encoding="utf-8", errors="ignore")
    )
    
    fname = truncate_filename(file_path.name)
    current_line = 0
    
    def process_and_output(lineno: int, line_content: str):
        if mode == "wallet":
            parsed = parse_wallet_line(line_content)
            if not parsed:
                return
            priv_raw, addr, parts = parsed
            wif_priv = normalize_priv_to_wif(priv_raw) or priv_raw
            word = parts[0] if len(parts) >= 3 else ""
            
            if not wif_priv or not addr:
                return
            
            first_col = f"{Fore.LIGHTBLACK_EX}{fname}{Style.RESET_ALL}:{Fore.LIGHTYELLOW_EX}{lineno}{Style.RESET_ALL}"
            bal_sat = local_db.get(addr, 0)
            bal_btc = sat_to_btc(bal_sat)
            
            # In local mode, we don't have EUR rate, show only BTC
            bal_disp = f"{Fore.GREEN}{bal_btc:.8f} BTC{Style.RESET_ALL}" if bal_btc > 0 else f"{Fore.RED}0.00000000 BTC{Style.RESET_ALL}"
            tqdm.write(format_output_line(first_col, addr, None, bal_disp, f"{Fore.RED}N/A{Style.RESET_ALL}"))
            
            if bal_btc > 0:
                if addr not in seen_addrs:
                    seen_addrs.add(addr)
                    with open(output_file, "a", encoding="utf-8") as f:
                        # Using 0.00 for EUR since we don't have rate without API
                        f.write(build_output_line(wif_priv, addr, f"{bal_btc:.8f}", "N/A", "0.00", word) + "\n")
        else:
            word = extract_word(line_content, mode)
            if not word:
                return
            
            first_col_base = f"{Fore.LIGHTBLACK_EX}{fname}{Style.RESET_ALL}:{Fore.LIGHTYELLOW_EX}{lineno}{Style.RESET_ALL} {Fore.WHITE}{word}{Style.RESET_ALL}"
            
            key_pairs = generate_key_pairs_sync(word, lowcase)
            if not key_pairs:
                return
            
            for wif_priv, addr, is_compressed in key_pairs:
                bal_sat = local_db.get(addr, 0)
                bal_btc = sat_to_btc(bal_sat)
                
                bal_disp = f"{Fore.GREEN}{bal_btc:.8f} BTC{Style.RESET_ALL}" if bal_btc > 0 else f"{Fore.RED}0.00000000 BTC{Style.RESET_ALL}"
                tqdm.write(format_output_line(first_col_base, addr, is_compressed, bal_disp, f"{Fore.RED}N/A{Style.RESET_ALL}"))
                
                if bal_btc > 0:
                    if addr not in seen_addrs:
                        seen_addrs.add(addr)
                        with open(output_file, "a", encoding="utf-8") as f:
                            f.write(build_output_line(wif_priv, addr, f"{bal_btc:.8f}", "N/A", "0.00", word) + "\n")
    
    try:
        with opener(file_path, "rt") as fh:
            for current_line, line in enumerate(fh, 1):
                if current_line <= start_line:
                    continue
                
                process_and_output(current_line, line)
                pbar.update(1)
                
                # Save resume every 100 lines
                if current_line % 100 == 0:
                    save_resume(resume_path, rel_path, current_line)
        
        # Mark as completed (-1)
        save_resume(resume_path, rel_path, -1)
        
    except KeyboardInterrupt:
        save_resume(resume_path, rel_path, current_line)
        raise
    except Exception:
        save_resume(resume_path, rel_path, current_line)
        raise


def load_local_database():
    """Load Legacy addresses from Loyce Club DB."""
    if not LOCAL_DB_PATH.exists():
        print(f"{Fore.RED}Local database not found. Download it from:")
        print(f"http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz")
        print(f"and place it at: {LOCAL_DB_PATH}{Style.RESET_ALL}")
        sys.exit(1)
    
    db = {}
    db_name = truncate_filename(LOCAL_DB_PATH.name)
    print(f"{Fore.LIGHTBLACK_EX}Loading Legacy addresses from{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{db_name}{Style.RESET_ALL}", end=" ", flush=True)
    
    with gzip.open(LOCAL_DB_PATH, "rt", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                addr = parts[0]
                if addr.startswith('1'):
                    try:
                        db[addr] = int(parts[1])
                    except ValueError:
                        continue
    
    print(f"{Fore.LIGHTYELLOW_EX}{len(db):,}{Style.RESET_ALL}")
    return db


def main():
    """Main entry point."""
    args = parse_args()
    print_banner()
    
    input_path = Path(args.input)
    output_file = args.output
    
    out_path = Path(output_file)
    if out_path.parent:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Load already saved addresses
    seen_addrs = set()
    if out_path.exists():
        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.strip().split(';')
                if len(parts) >= 2:
                    seen_addrs.add(parts[1])
    
    resume_path = get_resume_path(input_path)
    resume_file, resume_line = load_resume(resume_path)
    
    # Phase 1: Count lines
    files_with_info = []
    
    if args.mode == "wallet":
        if not input_path.is_file():
            print(f"{Fore.RED}Input must be a file in wallet mode{Style.RESET_ALL}")
            sys.exit(1)
        print(f"{Fore.LIGHTBLACK_EX}Counting lines of{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{truncate_filename(input_path.name)}{Style.RESET_ALL}", end=" ", flush=True)
        line_count = count_lines_fast(input_path)
        print(f"{Fore.LIGHTYELLOW_EX}{line_count:,}{Style.RESET_ALL}")
        files_with_info.append((input_path, input_path.name, line_count))
    else:
        if input_path.is_file():
            ext = input_path.suffix.lower()
            if ext not in ('.dic', '.txt', '.zst', '.gz'):
                print(f"{Fore.RED}Unsupported file extension: {ext}. Supported: .dic, .txt, .zst, .gz{Style.RESET_ALL}")
                sys.exit(1)
            print(f"{Fore.LIGHTBLACK_EX}Counting lines of{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{truncate_filename(input_path.name)}{Style.RESET_ALL}", end=" ", flush=True)
            line_count = count_lines_fast(input_path)
            print(f"{Fore.LIGHTYELLOW_EX}{line_count:,}{Style.RESET_ALL}")
            files_with_info.append((input_path, input_path.name, line_count))
        elif input_path.is_dir():
            temp_files = []
            for ext in ("*.dic", "*.txt", "*.zst", "*.gz"):
                temp_files.extend(input_path.rglob(ext))
            
            temp_files = sorted(temp_files, key=lambda x: str(x.relative_to(input_path)) if x.is_relative_to(input_path) else x.name)
            
            if not temp_files:
                print(f"{Fore.RED}No supported files found in directory: {input_path}{Style.RESET_ALL}")
                sys.exit(1)
                
            for fp in temp_files:
                rel = str(fp.relative_to(input_path)) if fp.is_relative_to(input_path) else fp.name
                print(f"{Fore.LIGHTBLACK_EX}Counting lines of{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{truncate_filename(fp.name)}{Style.RESET_ALL}", end=" ", flush=True)
                line_count = count_lines_fast(fp)
                print(f"{Fore.LIGHTYELLOW_EX}{line_count:,}{Style.RESET_ALL}")
                files_with_info.append((fp, rel, line_count))
        else:
            print(f"{Fore.RED}Input not found: {input_path}{Style.RESET_ALL}")
            sys.exit(1)
    
    # Load local DB
    local_db = load_local_database()
    
    # Calculate totals and handle resume
    total_lines = sum(x[2] for x in files_with_info)
    initial_offset = 0
    files_to_process = []
    
    if resume_file:
        found = False
        for fp, rp, lc in files_with_info:
            if found:
                files_to_process.append((fp, rp, 0))
            elif rp == resume_file or str(fp) == resume_file or fp.name == resume_file:
                found = True
                if resume_line == -1:
                    initial_offset += lc
                elif resume_line == 0:
                    initial_offset += 0
                    files_to_process.append((fp, rp, 0))
                else:
                    initial_offset += resume_line
                    files_to_process.append((fp, rp, resume_line))
            else:
                initial_offset += lc
        
        if not found:
            initial_offset = 0
            files_to_process = [(fp, rp, 0) for fp, rp, _ in files_with_info]
    else:
        files_to_process = [(fp, rp, 0) for fp, rp, _ in files_with_info]
    
    # Show stats
    print(f"{Fore.LIGHTBLACK_EX}Files:{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{len(files_to_process)} (of {len(files_with_info)} total){Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}Total rows:{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{total_lines:,}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}Already saved:{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{len(seen_addrs)}{Style.RESET_ALL}")
    if resume_file and resume_line != -1:
        print(f"{Fore.LIGHTBLACK_EX}Resume:{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{truncate_filename(resume_file)}:{resume_line}{Style.RESET_ALL}")
    elif resume_file and resume_line == -1:
        print(f"{Fore.LIGHTBLACK_EX}Resume:{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{truncate_filename(resume_file)}:completed{Style.RESET_ALL}")
    if args.lowcase:
        print(f"{Fore.LIGHTBLACK_EX}Lowercase:{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}enabled{Style.RESET_ALL}")
    print()
    
    # Setup progress bar
    bar_format = "{desc}: {percentage:5.1f}% |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
    pbar_total = total_lines if total_lines > 0 else None
    
    pbar = tqdm(
        total=pbar_total,
        initial=initial_offset,
        position=0,
        leave=True,
        bar_format=bar_format,
        unit="lines",
        colour="yellow",
        ncols=100,
        miniters=1,
        dynamic_ncols=True
    )
    pbar.set_description("Scanning")
    
    try:
        # Only local mode available now
        for fp, rp, start in files_to_process:
            scan_file(fp, rp, args.mode, args.lowcase, local_db,
                     output_file, seen_addrs, start, resume_path, pbar)
                        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted.{Style.RESET_ALL}")
    finally:
        pbar.close()
    
    print(f"\n{Fore.GREEN}Done.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
