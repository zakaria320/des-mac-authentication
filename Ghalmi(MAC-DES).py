import binascii
import string
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

def create_mac(plaintext, key):
    key = key.ljust(8, b'\0')[:8]
    des = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
    mac = des.encrypt(padded_text)[-DES.block_size:]
    return binascii.hexlify(mac).decode("utf-8")

def brute_force_mac(plaintext, target_mac):
    total_attempts = 0

    for first in string.ascii_uppercase:
        for second in string.ascii_lowercase:
            for third in string.digits:
                for fourth in "#@$%&*!":
                    key = f"{first}{second}{third}{fourth}".encode('utf-8')
                    mac = create_mac(plaintext, key)
                    total_attempts += 1

                    if total_attempts % 100 == 0:
                        print(f"Attempts: {total_attempts}, Testing key: {key.decode('utf-8')}")

                    if mac == target_mac:
                        print(f"\nSuccess! Found after {total_attempts} attempts")
                        return key.decode("utf-8")
    return None

def main():
    plain_text = "SecureClass2024!"
    key = b'Jx4#'
    mac = create_mac(plain_text, key)

    print("Part 1: Creating MAC")
    print(f"Plain Text: {plain_text}")
    print(f"Key: {key.decode('utf-8')}")
    print(f"MAC: {mac}")

    print("\nPart 2: Brute Force Attack")
    print("Starting brute force attack...")
    found_key = brute_force_mac(plain_text, mac)

    if found_key:
        print(f"Found key: {found_key}")
        verify_mac = create_mac(plain_text, found_key.encode('utf-8'))
        print(f"Original MAC: {mac}")
        print(f"Found key MAC: {verify_mac}")
        print(f"MAC verification: {'Success' if mac == verify_mac else 'Failed'}")
    else:
        print("Key not found.")

if __name__ == "__main__":
    main()
