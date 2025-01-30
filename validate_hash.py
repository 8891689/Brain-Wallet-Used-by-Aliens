#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import random
from collections import defaultdict
import hashlib
import re

# Attempt to import external hash algorithm libraries, skip if not installed
try:
    import blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False
    print("Warning: BLAKE3 hash algorithm requires the blake3 library, skipped.")

try:
    import xxhash
    XXHASH_AVAILABLE = True
except ImportError:
    XXHASH_AVAILABLE = False
    print("Warning: xxhash library is not installed, some hash algorithms have been skipped.")

# Define hash functions
def sha224_hash(data):
    return hashlib.sha224(data).digest()

def sha384_hash(data):
    return hashlib.sha384(data).digest()

def sha512_hash(data):
    return hashlib.sha512(data).digest()

def sha3_224_hash(data):
    return hashlib.sha3_224(data).digest()

def sha3_256_hash(data):
    return hashlib.sha3_256(data).digest()

def sha3_384_hash(data):
    return hashlib.sha3_384(data).digest()

def sha3_512_hash(data):
    return hashlib.sha3_512(data).digest()

def shake128_hash(data, length=64):
    return hashlib.shake_128(data).digest(length)

def shake256_hash(data, length=64):
    return hashlib.shake_256(data).digest(length)

def blake2b_hash(data):
    return hashlib.blake2b(data).digest()

def blake2s_hash(data):
    return hashlib.blake2s(data).digest()

def ripemd160_hash(data):
    try:
        return hashlib.new('ripemd160', data).digest()
    except ValueError:
        print("Warning: RIPEMD160 hash algorithm is not supported in your Python environment, skipped.")
        return None

def blake3_hash_func(data):
    if BLAKE3_AVAILABLE:
        try:
            return blake3.blake3(data).digest()
        except Exception as e:
            print(f"Warning: BLAKE3 hashing failed: {e}")
            return None
    else:
        print("Warning: BLAKE3 hash algorithm is not enabled, skipped.")
        return None

def xxhash64_hash(data):
    if XXHASH_AVAILABLE:
        try:
            return xxhash.xxh64(data).digest()
        except Exception as e:
            print(f"Warning: xxHash64 hashing failed: {e}")
            return None
    else:
        print("Warning: xxHash64 hash algorithm is not enabled, skipped.")
        return None

def xxhash128_hash(data):
    if XXHASH_AVAILABLE:
        try:
            return xxhash.xxh128(data).digest()
        except Exception as e:
            print(f"Warning: xxHash128 hashing failed: {e}")
            return None
    else:
        print("Warning: xxHash128 hash algorithm is not enabled, skipped.")
        return None

def sha256_hash(data):
    return hashlib.sha256(data).digest()

# Define supported algorithms and their hash functions
algorithms = [
    'SHA-224',
    'SHA-384',
    'SHA-512',
    'SHA3-224',
    'SHA3-256',
    'SHA3-384',
    'SHA3-512',
    'SHAKE128',
    'SHAKE256',
    'BLAKE2b',
    'BLAKE2s',
    'RIPEMD160',
    'BLAKE3',
    'xxHash64',
    'xxHash128'
]

# Ensure SHA-256 is executed last
algorithms.append('SHA-256')

# Define hash function mapping
hash_functions = {
    'SHA-224': sha224_hash,
    'SHA-384': sha384_hash,
    'SHA-512': sha512_hash,
    'SHA3-224': sha3_224_hash,
    'SHA3-256': sha3_256_hash,
    'SHA3-384': sha3_384_hash,
    'SHA3-512': sha3_512_hash,
    'SHAKE128': shake128_hash,
    'SHAKE256': shake256_hash,
    'BLAKE2b': blake2b_hash,
    'BLAKE2s': blake2s_hash,
    'RIPEMD160': ripemd160_hash,
    'BLAKE3': blake3_hash_func,
    'xxHash64': xxhash64_hash,
    'xxHash128': xxhash128_hash,
    'SHA-256': sha256_hash
}

# Define the raw data for hash algorithm usage counts
counts_data = """
SHA-224: 919988 times
SHA-384: 583339 times
SHA-512: 595376 times
SHA3-224: 97740 times
SHA3-256: 83834 times
SHA3-384: 483447 times
SHA3-512: 368382 times
SHAKE128: 743005 times
SHAKE256: 492113 times
BLAKE2b: 766478 times
BLAKE2s: 849511 times
RIPEMD160: 415450 times
BLAKE3: 478358 times
xxHash64: 23614 times
xxHash128: 137938 times
SHA-256: 722568 times
"""

def parse_usage_counts(counts_str):
    usage_counts = {}
    # Use regular expressions to parse each line
    pattern = re.compile(r'^\s*(\S+):\s*(\d+)\s*times\s*$')
    for line in counts_str.strip().split('\n'):
        match = pattern.match(line)
        if match:
            algo, count = match.groups()
            usage_counts[algo] = int(count)
        else:
            print(f"Warning: Unable to parse line: '{line}'")
    return usage_counts

def main():
    parser = argparse.ArgumentParser(description='Validate Multi-Algorithm Irreversible Hash Script')
    parser.add_argument('-p', '--password', type=str, required=True, help='Input password')
    parser.add_argument('-e', '--expected_hash', type=str, required=True, help='Expected final hash value (hexadecimal)')
    # Optional: Allow users to provide a custom usage counts file
    parser.add_argument('-c', '--counts_file', type=str, help='Usage counts file, each line formatted as "Algorithm: Count times"')

    args = parser.parse_args()

    # Get input data (password)
    data = args.password.encode()

    # Parse usage counts
    if args.counts_file:
        try:
            with open(args.counts_file, 'r', encoding='utf-8') as f:
                counts_str = f.read()
            usage_counts = parse_usage_counts(counts_str)
        except Exception as e:
            print(f"Error: Unable to read usage counts file: {e}")
            sys.exit(1)
    else:
        # Use the built-in counts_data
        usage_counts = parse_usage_counts(counts_data)

    # Check if all algorithms are defined in usage counts
    for algo in algorithms:
        if algo not in usage_counts:
            print(f"Error: Algorithm '{algo}' is not defined in the usage counts.")
            sys.exit(1)

    total_iterations = sum(usage_counts[algo] for algo in algorithms)
    print(f"Total hash iterations (sum of all algorithms): {total_iterations}\n")

    # Initialize counters
    algo_counts = defaultdict(int)

    # Execute hashing
    for algo in algorithms:
        count = usage_counts[algo]
        print(f"Starting algorithm {algo}, iterations: {count}")
        hash_func = hash_functions.get(algo)
        if not hash_func:
            print(f"Warning: Hash function for algorithm {algo} not found, skipped.")
            continue
        for i in range(1, count + 1):
            try:
                hashed = hash_func(data)
                if hashed:
                    data = hashed
                algo_counts[algo] += 1
                # Optional: Display progress during large iterations
                if i % 100000 == 0 or i == count:
                    print(f"  Algorithm {algo} iteration: {i}/{count}")
            except Exception as e:
                print(f"Error occurred while using {algo}: {e}")
                sys.exit(1)
        print(f"Completed {count} hash operations for algorithm {algo}.\n")

    # Output final hashed data (in hexadecimal)
    final_hash = data.hex()
    print("\nFinal hashed data (hexadecimal):")
    print(final_hash)

    # Output the usage count of each hash algorithm
    print("\nUsage count for each hash algorithm:")
    for algo in algorithms:
        print(f"{algo}: {algo_counts[algo]} times")

    # Validate the hash value
    expected_hash = args.expected_hash.lower()
    if final_hash.lower() == expected_hash:
        print("\nValidation successful: Final hash matches the expected value.")
    else:
        print("\nValidation failed: Final hash does not match the expected value.")
        print(f"Expected hash: {expected_hash}")
        print(f"Actual hash: {final_hash}")

if __name__ == "__main__":
    main()
