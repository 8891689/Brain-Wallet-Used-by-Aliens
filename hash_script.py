#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
from collections import defaultdict
import hashlib

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

def get_true_random_int(min_val, max_val):
    """
    Get a random integer in the range [min_val, max_val] from the system entropy source.
    Prefer reading from /dev/random, fallback to os.urandom if unavailable.
    """
    range_size = max_val - min_val + 1
    num_bits = range_size.bit_length()
    num_bytes = (num_bits + 7) // 8  # Round up to the nearest byte

    # Attempt to read from /dev/random
    try:
        with open("/dev/random", "rb") as f:
            random_bytes = f.read(num_bytes)
            if len(random_bytes) < num_bytes:
                raise ValueError("Unable to read enough random bytes from /dev/random.")
    except (FileNotFoundError, PermissionError, OSError):
        # If unable to read /dev/random, use os.urandom
        random_bytes = os.urandom(num_bytes)

    random_int = int.from_bytes(random_bytes, 'big')
    return min_val + (random_int % range_size)

def main():
    parser = argparse.ArgumentParser(description='Multi-Algorithm Irreversible Hash Script')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-R', action='store_true', help='Assign random hash iterations for each algorithm (minimum 1, maximum 1000000)')
    group.add_argument('-n', type=int, help='Assign fixed hash iterations for each algorithm (1-1000000)')
    parser.add_argument('-p', '--password', type=str, required=True, help='Input password')

    args = parser.parse_args()

    # Get input data (password)
    data = args.password.encode()

    # Determine hash iterations
    if args.R:
        # Assign random hash iterations for each algorithm (1-1000000)
        iterations_per_algo = {algo: get_true_random_int(1, 1000000) for algo in algorithms}
    else:
        # Assign fixed hash iterations for each algorithm (1-1000000)
        if not (1 <= args.n <= 1000000):
            print("Fixed hash iterations must be between 1 and 1000000.")
            sys.exit(1)
        iterations_per_algo = {algo: args.n for algo in algorithms}

    total_iterations = sum(iterations_per_algo.values())
    print(f"Total hash iterations (sum of all algorithms): {total_iterations}\n")

    # Initialize counters
    algo_counts = defaultdict(int)

    # Execute hashing
    for algo in algorithms:
        count = iterations_per_algo[algo]
        for _ in range(count):
            algo_counts[algo] += 1
            try:
                hash_func = hash_functions.get(algo)
                if hash_func:
                    hashed = hash_func(data)
                    if hashed:
                        data = hashed
            except Exception as e:
                print(f"Error occurred while using {algo}: {e}")
                sys.exit(1)

    # Output final hashed data (in hexadecimal)
    print("\nFinal hashed data (hexadecimal):")
    print(data.hex())

    # Output the usage count of each hash algorithm
    print("\nUsage count for each hash algorithm:")
    for algo in algorithms:
        print(f"{algo}: {algo_counts[algo]} times")

if __name__ == "__main__":
    main()
