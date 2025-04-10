import base64
from pwn import xor

# 1) Convert hex to base64
def hex_to_base64(hex_string):
    # Convert hex to bytes
    bytes_data = bytes.fromhex(hex_string)
    # Convert bytes to base64
    base64_data = base64.b64encode(bytes_data)
    return base64_data

assert hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

# 2) Fixed XOR
def fixed_xor(hex1, hex2):
    # Convert hex strings to bytes
    bytes1 = bytes.fromhex(hex1)
    bytes2 = bytes.fromhex(hex2)
    # XOR the two byte arrays
    xor_result = xor(bytes1, bytes2)
    return xor_result

assert fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == bytes.fromhex("746865206b696420646f6e277420706c6179")

# 3) Single-byte XOR cipher
def single_byte_xor_cipher_decrypt(hex_string):
    # Try all possible single-byte XOR keys (0x00 to 0xFF)
    best_score = 0
    best_key = None
    best_decrypted = None
    for key in range(256):
        # XOR the hex string with the key
        decrypted = xor(bytes.fromhex(hex_string), bytes([key]))
        # Calculate the score based on frequency analysis
        score = sum([decrypted.count(c) for c in b'etaoin shrdlu'])
        if score > best_score:
            best_score = score
            best_key = key
            best_decrypted = decrypted
    return best_key, best_score, best_decrypted

assert single_byte_xor_cipher_decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736") == (88, 23, b"Cooking MC's like a pound of bacon")

# 4) Detect single-character XOR
with open("4.txt", "r") as f:
    hex_strings = f.readlines()
    best_score = 0
    best_key = None
    best_decrypted = None
    for hex_string in hex_strings:
        hex_string = hex_string.strip()
        key, score, decrypted = single_byte_xor_cipher_decrypt(hex_string)
        if score > best_score:
            best_score = score
            best_key = key
            best_decrypted = decrypted
    assert best_key == 53
    assert best_score == 21
    assert best_decrypted == b"Now that the party is jumping\n"

# 5) Implement repeating-key XOR
with open("5.txt", "r") as f:
    plaintext = f.read().strip()
    key = b"ICE"
    ciphertext = xor(plaintext.encode(), key)
    ciphertext_hex = ciphertext.hex()
    assert ciphertext_hex == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

# 6) Break repeating-key XOR
def hamming_distance(bytes1, bytes2):
    assert len(bytes1) == len(bytes2), "Byte arrays must be of equal length"
    # Calculate the Hamming distance between two byte arrays
    return sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(bytes1, bytes2))

assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37    

def find_key_size(ciphertext):
    # Find the key size that minimizes the normalized Hamming distance
    min_distance = float('inf')
    best_key_size = None
    for key_size in range(2, 41):
        # Split the ciphertext into blocks of the key size
        blocks = [ciphertext[i:i+key_size] for i in range(0, len(ciphertext), key_size)]
        # Calculate the average Hamming distance between the blocks
        distances = []
        for i in range(len(blocks) - 1):
            for j in range(i + 1, len(blocks)):
                if len(blocks[i]) == len(blocks[j]):
                    distances.append(hamming_distance(blocks[i], blocks[j]))
        if distances:
            avg_distance = sum(distances) / len(distances)
            normalized_distance = avg_distance / key_size
            if normalized_distance < min_distance:
                min_distance = normalized_distance
                best_key_size = key_size
    return best_key_size, min_distance

with open("6.txt", "r") as f:
    ciphertext = base64.b64decode(f.read())
    key_size, normalized_distance = find_key_size(ciphertext)
    assert key_size == 29
    assert round(normalized_distance, 2) == 2.79

    # Initialize the key as empty byte array
    key = bytearray()
    # Split the ciphertext into blocks of the key size
    blocks = [ciphertext[i:i + key_size] for i in range(0, len(ciphertext), key_size)]
    # Transpose the blocks (1st character of each block, 2nd character of each block, etc.)
    transposed_blocks = [bytes([blocks[j][i] for j in range(len(blocks)) if i < len(blocks[j])]) for i in range(key_size)]

    # For each transposed block, find the best single-byte XOR key
    for block in transposed_blocks:
        best_key_byte, _, _ = single_byte_xor_cipher_decrypt(block.hex())
        key.append(best_key_byte)
    # Decrypt the ciphertext using the found key
    decrypted = xor(ciphertext, bytes(key))

with open("6_output.txt", "wb") as f:
    f.write(decrypted)

# 7) AES in ECB mode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def aes_ecb_decrypt(ciphertext, key):
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    # Decrypt the ciphertext
    plaintext = cipher.decrypt(ciphertext)
    # Unpad the plaintext
    unpadded_plaintext = unpad(plaintext, AES.block_size)
    return unpadded_plaintext

with open("7.txt", "r") as f:
    # Read the base64 encoded ciphertext
    ciphertext = base64.b64decode(f.read())
    # Define the key
    key = b"YELLOW SUBMARINE"
    # Decrypt the ciphertext
    decrypted = aes_ecb_decrypt(ciphertext, key)

with open("7_output.txt", "wb") as f:
    f.write(decrypted)

# 8) Detect AES in ECB mode
def detect_ecb(bytes_data):
    # Split the ciphertext into blocks of 16 bytes
    blocks = [bytes_data[i:i + 16] for i in range(0, len(bytes_data), 16)]
    # Count the number of unique blocks
    unique_blocks = set(blocks)
    # If there are fewer unique blocks than total blocks, ECB mode is likely used
    return len(unique_blocks) < len(blocks)

with open("8.txt", "r") as f:
    # Read the ciphertexts
    ciphertexts = [bytes.fromhex(line.strip()) for line in f.readlines()]
    # Check each ciphertext for ECB mode
    ecb_ciphertexts = [ciphertext for ciphertext in ciphertexts if detect_ecb(ciphertext)]
    # Only one ciphertext should be in ECB mode
    assert len(ecb_ciphertexts) == 1