from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 1. Given parameters
initial_state = [
    0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1
]
taps = [63, 61, 60, 58]
encrypted_flag_hex = "8f0e6d0f5b0dc1db201948b9e0cebd8f65f3dbc3c00ee080eeede2138a5175fd38338e7e04fbddef0c6260a4eb758417"


# 2. Generate the 128-bit LFSR sequence
def generate_lfsr_sequence(state, taps, length):
    seq = []
    current_state = list(state)
    for _ in range(length):
        out_bit = current_state[0]
        seq.append(out_bit)

        # Calculate feedback bit using the specified taps
        feedback = 0
        for tap in taps:
            feedback ^= current_state[tap]

        # Shift left and append new bit
        current_state = current_state[1:] + [feedback]
    return seq


sequence_bits = generate_lfsr_sequence(initial_state, taps, 128)

# 3. Convert the 128 bits into a 16-byte AES key
key_bytes = bytearray()
for i in range(0, 128, 8):
    chunk = sequence_bits[i:i + 8]
    byte_val = int("".join(map(str, chunk)), 2)
    key_bytes.append(byte_val)

print(f"[*] Derived AES Key (Hex): {key_bytes.hex()}")

# 4. Decrypt the AES-ECB encrypted flag
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
cipher = AES.new(key_bytes, AES.MODE_ECB)

# Decrypt and unpad to retrieve plaintext
padded_flag = cipher.decrypt(encrypted_flag)
try:
    flag = unpad(padded_flag, AES.block_size).decode('utf-8')
    print(f"[*] Decrypted Flag: {flag}")
except ValueError:
    # Fallback in case padding wasn't strictly PKCS#7 standard
    print(f"[*] Decrypted Flag (Raw): {padded_flag}")