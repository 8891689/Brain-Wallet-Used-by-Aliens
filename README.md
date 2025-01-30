# Brain Wallet Used by Aliens

## Introduction
This project is a powerful multi-algorithm random irreversible encryption script that can process input data with **random encryption iterations ranging from 1 to 100 million or even a trillion times per algorithm**, making the encryption result impossible to reverse-engineer.

The core features of this script include **custom passwords + 16 encryption algorithms with multiple random hash iterations + multiple layers of encryption algorithm combinations**, forming a **trillion-base encryption** scheme that is difficult to crack, even with immense computational power.

## Features
- **16 encryption algorithms** covering SHA, BLAKE, RIPEMD, xxHash, and other hash algorithms.
- **Random encryption iterations (1 to 100 million times)** to ensure uniqueness and security.
- **Completely irreversible**, generating different encryption results each time it runs.
- **Multiple hash algorithm combinations** to ensure data unpredictability.
- **Automatic detection of supported encryption algorithms**, such as BLAKE3 and xxHash.

## The Power of Trillion-base Encryption
### Compared to Bitcoin Private Keys
Bitcoin private keys are **256-bit random numbers**, usually represented as a **64-character hexadecimal string**, i.e., **base-16**. In contrast, this script encrypts using a **100-million base system**, where the input data undergoes billions of transformations with different hash algorithms, making its complexity far greater than a Bitcoin private key.

- **Total possibilities of a Bitcoin private key:** 2^256 ≈ 10^77
- **Trillion-base encryption complexity:** Since this program uses **16 different hash algorithms, each digit being in base 100 million**, the total possible combinations reach **(10^8)^16 = 10^128**, which is several orders of magnitude greater than Bitcoin's private key security.

### Compared to Standard Wallet Mnemonics
Standard encrypted wallets use **BIP39 mnemonic phrases**, typically consisting of **12 or 24 mnemonic words**. The total possible combinations depend on **2048-word choices**, for example:

- **12-word mnemonic:** 2048^12 ≈ 10^39
- **24-word mnemonic:** 2048^24 ≈ 10^78

In contrast, this **trillion-base encryption** method involves **16 hash algorithms, equivalent to 16 digits, each with 100 million possible values**, significantly surpassing the security of a 24-word mnemonic phrase. Therefore, compared to standard wallet mnemonics, this script provides a far more unpredictable encryption outcome.

Additionally, this program allows users to provide a custom password as the initial input, further enhancing security. Users can also customize the numerical base; the higher the value, the longer the encryption time. A regular computer can complete trillion-base encryption within minutes, making it even more complex and unpredictable than Bitcoin private keys and mnemonics.

### Adjusting the Script
For stronger encryption, modify the following parameters in the script: (1, 1000000) and (1 <= args.n <= 1,000,000). The higher the value, the slower the encryption; adjust according to actual needs.

```python
if args.R:
    # Assign random hash iterations for each algorithm (1-1,000,000)
    iterations_per_algo = {algo: get_true_random_int(1, 1000000) for algo in algorithms}
else:
    # Assign fixed hash iterations for each algorithm (1-1,000,000)
    if not (1 <= args.n <= 1000000):
        print("Fixed hash iterations must be between 1 and 1000000.")
        sys.exit(1)
    iterations_per_algo = {algo: args.n for algo in algorithms}
```


## Supported Hash Algorithms
This script supports the following 16 hash algorithms:

1. SHA-224
2. SHA-384
3. SHA-512
4. SHA3-224
5. SHA3-256
6. SHA3-384
7. SHA3-512
8. SHAKE128
9. SHAKE256
10. BLAKE2b
11. BLAKE2s
12. RIPEMD160
13. BLAKE3 (requires `blake3` library)
14. xxHash64 (requires `xxhash` library)
15. xxHash128 (requires `xxhash` library)
16. SHA-256 (ensuring at least one standard hash value)

## Setting Up a Virtual Environment
It is recommended to use a virtual environment to manage dependencies and avoid conflicts with other projects.

**Using `venv`:**
```bash
python3 -m venv venv
```

**Activate the Virtual Environment:**

- **On Windows:**
  ```bash
  venv\Scripts\activate
  ```
- **On Unix or MacOS:**
  ```bash
  source venv/bin/activate
  ```

After activation, your terminal prompt should start with `(venv)`.

## Installing Dependencies
Some algorithms require additional Python libraries. Install the necessary dependencies using:
```sh
pip install blake3 xxhash
```

## Usage

### 1. Random Iteration Encryption (Each algorithm encrypts randomly between 1-100,000,000 times)
```sh
python script.py -R -p your_password
```

### 2. Fixed Iteration Encryption (Each algorithm executes a specified number of times, between 1-100,000,000)
```sh
python script.py -n 5000000 -p your_password
```
```sh
Example

python3 hash_script.py -p your_password -R
Total hash iterations (sum of all algorithms): 7761141


Final hashed data (hexadecimal):
cbeb88d35755124cadeac0edac3e492a6a8fbfeb20477a9a4a311d6ae2249d3b

Usage count for each hash algorithm:
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
```

## Verification Script `validate_hash.py`

Use the generated result and paste it into `validate_hash.py`, 


.# Define the raw data for hash algorithm usage counts

counts_data = """
The results obtained from the above calculations here are consistent with the correctness of the data. 

"""

```sh
.# Define the raw data for hash algorithm usage counts
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
```

Example

```sh
python3 validate_hash.py -p your_password -e cbeb88d35755124cadeac0edac3e492a6a8fbfeb20477a9a4a311d6ae2249d3b

Final hashed data (hexadecimal):
cbeb88d35755124cadeac0edac3e492a6a8fbfeb20477a9a4a311d6ae2249d3b

Usage count for each hash algorithm:
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
```
Validation successful: Final hash matches the expected value.


If the hash matches, the validation is successful.

## BTC Private Key to Various Addresses
### Install Dependencies
Ensure you have the required Python libraries installed:
```sh
pip install ecdsa base58 bech32
```

### Example Execution
```sh
python3 key.addresses.py <encrypted_result>

python3 key.addresses.py cbeb88d35755124cadeac0edac3e492a6a8fbfeb20477a9a4a311d6ae2249d3b
Raw Private Key (Hex): cbeb88d35755124cadeac0edac3e492a6a8fbfeb20477a9a4a311d6ae2249d3b
WIF Private Key: L4472t6MWfLnCd6wAn76WZb89Sk8wQho1RzaV1j4u6wwGpbWz81W
Compressed Public Key: 025428d83612c01f34208ad41e6c19402b4c0e8a297c5f72389cca3e0c4d5ad9aa
Private Key (Raw): cbeb88d35755124cadeac0edac3e492a6a8fbfeb20477a9a4a311d6ae2249d3b
Uncompressed Public Key: 045428d83612c01f34208ad41e6c19402b4c0e8a297c5f72389cca3e0c4d5ad9aa47a669fe1a4f633dcdda2ff9ed7b37db22f3578d92407375211894c3e59e7b7e

=== Addresses Generated from Compressed Public Key ===
Base58Check Address: 1N4rHZ9YeAn8rs772nmuZwoR3KeJ3EnthM
P2PKH (Starts with 1) Address (Compressed): 1N4rHZ9YeAn8rs772nmuZwoR3KeJ3EnthM
Base58Check Address: 3NksD6dzC56Wx2oY9tSVzaAMBqw1aevL4Y
P2SH (Starts with 3) Address (Compressed): 3NksD6dzC56Wx2oY9tSVzaAMBqw1aevL4Y
Bech32 (Starts with bc1) Address (Compressed): bc1quu2s0h556s7y3f4lza3mts4y6j00geflfra4rg
Bech32m (Starts with bc1p) Address (Compressed): bc1puu2s0h556s7y3f4lza3mts4y6j00geflza27wr

=== Addresses Generated from Uncompressed Public Key ===
Base58Check Address: 15DykFAoQRRzd6EUi8MMZi4ooDuydCVSvY
P2PKH (Starts with 1) Address (Uncompressed): 15DykFAoQRRzd6EUi8MMZi4ooDuydCVSvY
Base58Check Address: 35uzfnfExKkNiFvuqE1wzLRjwkChGuLwRb
P2SH (Starts with 3) Address (Uncompressed): 35uzfnfExKkNiFvuqE1wzLRjwkChGuLwRb
Bech32 (Starts with bc1) Address (Uncompressed): bc1q9e2d6rcfx8r9mgxnllmesdltxwwxas0qfg3q2r
Bech32m (Starts with bc1p) Address (Uncompressed): bc1p9e2d6rcfx8r9mgxnllmesdltxwwxas0qzkxt8g

```

This will generate various Bitcoin addresses from the encrypted private key.

## Use Cases
- **Password Storage:** Enhancing password security with random hash iterations.
- **Data Signing:** Preventing data tampering and ensuring integrity.
- **Encrypted Communication:** Providing highly obfuscated hash encryption for communication data.
- **Cryptocurrency Security:** Protecting digital assets and enhancing security.

# Sponsorship
If this project has been helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!

- **BTC:** bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
- **ETH:** 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
- **DOGE:** DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
- **TRX:** TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4

# Disclaimer
This tool is intended for educational and research purposes only. Users are responsible for any risks and liabilities arising from the use of this tool. The developers are not liable for any losses resulting from the use of this tool.

## Contribution
If you have any suggestions for improvement or encounter any issues, feel free to contribute!
