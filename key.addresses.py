from ecdsa import SigningKey, SECP256k1
import hashlib
import binascii
import base58
from bech32 import bech32_encode, convertbits
import sys

def private_key_to_uncompressed_public_key(private_key_hex):
    print(f"Private Key (Raw): {private_key_hex}")
    sk = SigningKey.from_string(binascii.unhexlify(private_key_hex), curve=SECP256k1)
    vk = sk.get_verifying_key()

    # Uncompressed Public Key
    public_key_uncompressed = b'\x04' + vk.to_string()
    print(f"Uncompressed Public Key: {binascii.hexlify(public_key_uncompressed).decode()}")

    return public_key_uncompressed

def private_key_to_compressed_public_key(private_key_hex):
    sk = SigningKey.from_string(binascii.unhexlify(private_key_hex), curve=SECP256k1)
    vk = sk.get_verifying_key()

    # Compressed Public Key
    x = vk.to_string()[:32]
    y = vk.to_string()[32:]
    if int.from_bytes(y, 'big') % 2 == 0:
        prefix = b'\x02'
    else:
        prefix = b'\x03'
    public_key_compressed = prefix + x
    print(f"Compressed Public Key: {binascii.hexlify(public_key_compressed).decode()}")

    return public_key_compressed

def hash160(pubkey):
    sha256 = hashlib.sha256(pubkey).digest()
    #print(f"SHA-256: {binascii.hexlify(sha256).decode()}")

    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    #print(f"RIPEMD-160: {binascii.hexlify(ripemd160).decode()}")

    return ripemd160

def base58_check(version, payload):
    versioned_payload = version + payload
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    #print(f"Checksum: {binascii.hexlify(checksum).decode()}")

    address = base58.b58encode(versioned_payload + checksum)
    print(f"Base58Check Address: {address.decode()}")

    return address

def public_key_to_address(pubkey, address_type='P2PKH'):
    if address_type == 'P2PKH':
        version = b'\x00'
        payload = hash160(pubkey)
        return base58_check(version, payload).decode()
    elif address_type == 'P2SH':
        version = b'\x05'
        payload = hash160(pubkey)
        return base58_check(version, payload).decode()
    elif address_type == 'BECH32':
        witness_version = 0
        witness_program = hash160(pubkey)
        converted = convertbits(witness_program, 8, 5)
        return bech32_encode('bc', [witness_version] + converted)
    elif address_type == 'BECH32M':
        witness_version = 1
        witness_program = hash160(pubkey)
        converted = convertbits(witness_program, 8, 5)
        return bech32_encode('bc', [witness_version] + converted)
    else:
        raise ValueError("Unsupported address type")

def wif_to_private_key(wif):
    decoded = base58.b58decode(wif)
    if len(decoded) not in [37, 38]:
        raise ValueError("Invalid WIF length")
    checksum = decoded[-4:]
    version_and_key = decoded[:-4]
    calculated_checksum = hashlib.sha256(hashlib.sha256(version_and_key).digest()).digest()[:4]
    if checksum != calculated_checksum:
        raise ValueError("Invalid WIF checksum")
    version = version_and_key[0]
    if version != 0x80:
        raise ValueError("Invalid WIF version")
    if len(version_and_key) == 34 and version_and_key[-1] == 0x01:
        # Compressed WIF
        private_key = version_and_key[1:-1]
        compressed = True
    elif len(version_and_key) == 33:
        # Uncompressed WIF
        private_key = version_and_key[1:]
        compressed = False
    else:
        raise ValueError("Invalid WIF format")
    return private_key.hex(), compressed

def private_key_to_wif(private_key_hex, compressed=True):
    private_key = binascii.unhexlify(private_key_hex)
    versioned_key = b'\x80' + private_key
    if compressed:
        versioned_key += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(versioned_key).digest()).digest()[:4]
    wif = base58.b58encode(versioned_key + checksum).decode()
    return wif

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 calculate_address.py <Private Key (Hex or WIF)>")
        sys.exit(1)
    
    input_key = sys.argv[1]
    
    if input_key.startswith(('5', 'K', 'L')):
        try:
            private_key_hex, compressed = wif_to_private_key(input_key)
            print(f"WIF Private Key: {input_key}")
            print(f"Raw Private Key (Hex): {private_key_hex}")
        except Exception as e:
            print(f"Failed to parse WIF: {e}")
            sys.exit(1)
    else:
        private_key_hex = input_key
        # Verify if it's a valid hex string
        try:
            binascii.unhexlify(private_key_hex)
        except binascii.Error:
            print("Invalid private key format. Please enter a valid hex string or WIF.")
            sys.exit(1)
        # Default to compressed
        wif = private_key_to_wif(private_key_hex, compressed=True)
        print(f"Raw Private Key (Hex): {private_key_hex}")
        print(f"WIF Private Key: {wif}")
    
    # Generate compressed and uncompressed public keys
    if input_key.startswith(('5', 'K', 'L')):
        # If input is WIF, generate public keys based on compression flag
        if compressed:
            public_key_compressed = private_key_to_compressed_public_key(private_key_hex)
            # Also generate uncompressed public key
            public_key_uncompressed = private_key_to_uncompressed_public_key(private_key_hex)
        else:
            # Uncompressed WIF
            public_key_uncompressed = private_key_to_uncompressed_public_key(private_key_hex)
            # Also generate compressed public key
            public_key_compressed = private_key_to_compressed_public_key(private_key_hex)
    else:
        # If input is raw private key, assume compressed
        public_key_compressed = private_key_to_compressed_public_key(private_key_hex)
        public_key_uncompressed = private_key_to_uncompressed_public_key(private_key_hex)
    
    # Generate addresses
    print("\n=== Addresses Generated from Compressed Public Key ===")
    p2pkh_address_compressed = public_key_to_address(public_key_compressed, 'P2PKH')
    print(f"P2PKH (Starts with 1) Address (Compressed): {p2pkh_address_compressed}")
    
    p2sh_address_compressed = public_key_to_address(public_key_compressed, 'P2SH')
    print(f"P2SH (Starts with 3) Address (Compressed): {p2sh_address_compressed}")
    
    bech32_address_compressed = public_key_to_address(public_key_compressed, 'BECH32')
    print(f"Bech32 (Starts with bc1) Address (Compressed): {bech32_address_compressed}")
    
    bech32m_address_compressed = public_key_to_address(public_key_compressed, 'BECH32M')
    print(f"Bech32m (Starts with bc1p) Address (Compressed): {bech32m_address_compressed}")
    
    print("\n=== Addresses Generated from Uncompressed Public Key ===")
    p2pkh_address_uncompressed = public_key_to_address(public_key_uncompressed, 'P2PKH')
    print(f"P2PKH (Starts with 1) Address (Uncompressed): {p2pkh_address_uncompressed}")
    
    p2sh_address_uncompressed = public_key_to_address(public_key_uncompressed, 'P2SH')
    print(f"P2SH (Starts with 3) Address (Uncompressed): {p2sh_address_uncompressed}")
    
    bech32_address_uncompressed = public_key_to_address(public_key_uncompressed, 'BECH32')
    print(f"Bech32 (Starts with bc1) Address (Uncompressed): {bech32_address_uncompressed}")
    
    bech32m_address_uncompressed = public_key_to_address(public_key_uncompressed, 'BECH32M')
    print(f"Bech32m (Starts with bc1p) Address (Uncompressed): {bech32m_address_uncompressed}")

if __name__ == "__main__":
    main()
