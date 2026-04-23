import exiftool
import re
import binascii
import sys

image_path = "image.jpg"

# Regex to find a long, continuous string of hex characters.
# An RSA private key will be quite long, so we look for 100+ hex chars.
hex_pattern = re.compile(r'^[0-9a-fA-F]{100,}$')

print(f"[*] Reading metadata from {image_path}...")

try:
    # Open the ExifTool wrapper
    with exiftool.ExifToolHelper() as et:
        # get_metadata returns a list of dictionaries, we want the first file [0]
        metadata = et.get_metadata(image_path)[0]

        found_key = False

        for tag, value in metadata.items():
            # Convert value to string to check it safely
            str_val = str(value)

            # Clean up the string just in case there are spaces or newlines hiding the hex
            clean_val = str_val.replace('\n', '').replace(' ', '').replace('\r', '')

            # Check if the value is a giant hex string
            if hex_pattern.match(clean_val):
                print(f"\n[!!!] BINGO! Found a long hex string in the '{tag}' tag.")
                print(f"[*] Hex preview: {clean_val[:50]}...{clean_val[-50:]}")

                print("\n[*] Attempting to convert hex back to PEM file (Hint 2)...")
                try:
                    # Convert the hex string back into raw bytes
                    key_bytes = binascii.unhexlify(clean_val)

                    # Write the bytes to a .pem file
                    with open("private_key.pem", "wb") as f:
                        f.write(key_bytes)

                    print("[+] Success! Private key saved as 'private_key.pem'")
                    found_key = True
                    break  # We found what we need, stop searching

                except binascii.Error as e:
                    print(f"[-] Error converting hex: {e}")

        if not found_key:
            print("[-] Could not find a long hex string in the metadata.")
            print("[*] Here is a dump of the metadata to inspect manually:\n")
            for tag, value in metadata.items():
                print(f"{tag}: {str(value)[:100]}")  # Print first 100 chars of each tag

except NameError:
    print("[-] It looks like the exiftool module didn't load properly.")
    print("[-] Make sure you installed it via: pip install PyExifTool")
except Exception as e:
    print(f"[-] An error occurred: {e}")
    print("[-] Ensure the 'exiftool' command-line utility is installed on your OS.")