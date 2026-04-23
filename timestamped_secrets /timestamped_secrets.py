from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# The ciphertext provided in message.txt
ciphertext_hex = "71cd3848348a45b82789f710c3321aceab2171e004200b57fe9cc64d4ea33cec"
ciphertext = bytes.fromhex(ciphertext_hex)

# The timestamp provided in the hint
hint_timestamp = 1770242610

print("Brute-forcing the timestamp...")

# Check a small window of timestamps around the hint (e.g., +/- 100 seconds)
for ts in range(hint_timestamp - 100, hint_timestamp + 100):

    # Recreate the key generation process exactly as the encryption script did
    key = sha256(str(ts).encode()).digest()[:16]

    # Initialize AES in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    try:
        # Attempt to decrypt and unpad
        # If the key is wrong, unpad() will throw a ValueError due to invalid PKCS7 padding
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # Check if the resulting plaintext looks like our flag
        if b"picoCTF{" in decrypted:
            print(f"\n[+] Success! Exact timestamp used: {ts}")
            print(f"[+] Flag: {decrypted.decode('utf-8')}")
            break

    except ValueError:
        # Invalid padding means incorrect key, continue to the next timestamp
        pass