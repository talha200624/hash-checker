#!/usr/bin/env python3
"""hashcheck - File hash calculator and verifier.

Usage examples:
  python hashcheck.py file.iso
  python hashcheck.py file.iso -c <expected_hash>
  python hashcheck.py file1 file2 -a md5
  python hashcheck.py folder/ -r
  python hashcheck.py --verify-list SHA256SUMS
"""
import argparse
import hashlib
import hmac
import os
import sys

# If tqdm is installed a progress bar is shown; otherwise the tool still works.
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]

# Detect the algorithm from the hex digest length
LENGTH_TO_ALGORITHM = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


def detect_algorithm(hash_value):
    """Guess the algorithm from the hash length, or return None if unknown."""
    return LENGTH_TO_ALGORITHM.get(len(hash_value.strip()))


def file_hash(path, algorithm="sha256", chunk_size=1024 * 1024, show_progress=False):
    """Read the file in chunks and return its hex digest."""
    h = hashlib.new(algorithm)
    total = os.path.getsize(path)
    bar = None
    if show_progress and tqdm and total > 10 * 1024 * 1024:  # only above 10 MB
        bar = tqdm(total=total, unit="B", unit_scale=True,
                   desc=os.path.basename(path), leave=False)
    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
                if bar:
                    bar.update(len(chunk))
    finally:
        if bar:
            bar.close()
    return h.hexdigest()


def hashes_match(computed, expected):
    """Compare two hashes, ignoring case and surrounding whitespace."""
    return hmac.compare_digest(computed.lower(), expected.strip().lower())


def collect_files(paths, recursive):
    """Yield files from the given paths; directories are scanned."""
    for path in paths:
        if os.path.isdir(path):
            if recursive:
                for root, _, files in os.walk(path):
                    for name in sorted(files):
                        yield os.path.join(root, name)
            else:
                for name in sorted(os.listdir(path)):
                    full = os.path.join(path, name)
                    if os.path.isfile(full):
                        yield full
        else:
            yield path


def verify_list(list_path, chosen_algorithm):
    """Read a sha256sum-style file and verify every entry.

    Line format:  <hash>  <filename>   (the filename may be prefixed with *)
    """
    base_dir = os.path.dirname(os.path.abspath(list_path))
    ok = bad = missing = 0

    with open(list_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                print(f"⚠️  Could not parse line {line_no}: {line}")
                missing += 1
                continue

            expected, name = parts
            name = name.lstrip("*")
            path = os.path.join(base_dir, name)
            algorithm = chosen_algorithm or detect_algorithm(expected)
            if not algorithm:
                print(f"⚠️  {name}: could not determine the algorithm from the hash length")
                missing += 1
                continue

            try:
                result = file_hash(path, algorithm, show_progress=True)
            except FileNotFoundError:
                print(f"❓ {name}: file not found")
                missing += 1
                continue
            except PermissionError:
                print(f"🚫 {name}: permission denied")
                missing += 1
                continue

            if hashes_match(result, expected):
                print(f"✅ {name}: OK")
                ok += 1
            else:
                print(f"❌ {name}: MISMATCH")
                bad += 1

    print(f"\nSummary: {ok} OK, {bad} mismatched, {missing} missing/unreadable")
    return bad == 0 and missing == 0


def main():
    p = argparse.ArgumentParser(description="File hash calculator and verifier")
    p.add_argument("paths", nargs="*", help="File or directory paths")
    p.add_argument("-a", "--algorithm", choices=ALGORITHMS,
                   help="Hash algorithm (default: sha256, auto-detected when -c is used)")
    p.add_argument("-c", "--expected", help="Expected hash value to compare against")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="Scan directories including subdirectories")
    p.add_argument("-l", "--verify-list", metavar="FILE",
                   help="Verify a sha256sum-style checksum list")
    args = p.parse_args()

    # Mode 1: checksum list verification
    if args.verify_list:
        try:
            ok = verify_list(args.verify_list, args.algorithm)
        except FileNotFoundError:
            print(f"Error: checksum list not found: {args.verify_list}")
            return 2
        return 0 if ok else 1

    if not args.paths:
        p.error("at least one file path or --verify-list is required")

    # Algorithm: user's choice, else detected from the expected hash, else sha256
    algorithm = args.algorithm
    if not algorithm and args.expected:
        algorithm = detect_algorithm(args.expected)
        if algorithm:
            print(f"ℹ️  Algorithm detected from hash length: {algorithm.upper()}")
        else:
            print("Error: the expected hash length doesn't match a known algorithm, "
                  "use -a to choose one.")
            return 2
    algorithm = algorithm or "sha256"

    files = list(collect_files(args.paths, args.recursive))
    if args.expected and len(files) != 1:
        print("Error: -c can only be used with a single file.")
        return 2

    has_problem = False
    for path in files:
        try:
            result = file_hash(path, algorithm, show_progress=True)
        except FileNotFoundError:
            print(f"❓ {path}: file not found")
            has_problem = True
            continue
        except PermissionError:
            print(f"🚫 {path}: permission denied")
            has_problem = True
            continue
        except OSError as e:
            print(f"⚠️  {path}: {e}")
            has_problem = True
            continue

        print(f"{result}  {path}")

        if args.expected:
            if hashes_match(result, args.expected):
                print(f"✅ {algorithm.upper()} matches, the file is intact.")
            else:
                print("❌ Hash MISMATCH! The file may be corrupted or modified.")
                has_problem = True

    return 1 if has_problem else 0


if __name__ == "__main__":
    sys.exit(main())
