import sys, getpass
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import struct
import time

########
#Creating an initial login message according to SiFT protocol for client
########

# Generate tempoerary AES key and random header values for login session

tk = get_random_bytes(32)      # 32-byte AES key
rnd = get_random_bytes(6)      # 6-byte random value for header
sqn = (1).to_bytes(2, "big")   # sequence number starts at 1
nonce = sqn + rnd              # 8 bytes total (as required by SiFT)

# builds login payload 
timestamp = str(time.time_ns())
username = "alice" # 
password = "aaa"
client_random_hex = get_random_bytes(16).hex()

payload_str = f"{timestamp}\n{username}\n{password}\n{client_random_hex}"
payload_bytes = payload_str.encode("utf-8")
# currently 62 

# encrypts login payload using AES-GCM
cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=12)
epd, mac = cipher.encrypt_and_digest(payload_bytes)

# Encrypt temporary key (tk) using RSA-OAEP
# Load server public key (PEM)
with open("pubkeyfile copy.pem", "rb") as f:
    pubkey = RSA.import_key(f.read())

rsa_cipher = PKCS1_OAEP.new(pubkey)
etk = rsa_cipher.encrypt(tk)   # 256 bytes for a 2048-bit RSA key

#Building final login message
ver = b"\x01\x00"              # version 1.0
typ = b"\x00\x00"              # login_req
rsv = b"\x00\x00"              # reserved

total_len = 16 + len(epd) + len(mac) + len(etk)
len_bytes = struct.pack(">H", total_len)

hdr = ver + typ + len_bytes + sqn + rnd + rsv

mtp_message = hdr + epd + mac + etk

print("Header:", hdr.hex(), "Length:", len(hdr))
print("Encrypted payload (epd):", epd.hex())
print("MAC:", mac.hex())
print("Encrypted temporary key (etk):", etk.hex())
print("Final message length:", len(mtp_message))



########
# Trying to unlock message using saved private key
########

def load_keypair(privkeyfile):
    #passphrase = input('Enter a passphrase to decode the saved private key: ')
    passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase=passphrase)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

def server_response(mtp_message: bytes):
    hdr = mtp_message[0:16]
    privkeyfile = 'privkeyfile copy.pem'
    etk = mtp_message[-256:]  # encrypted AES key from the login message

    #create the RSA cipher object with server private key
    keypair = load_keypair(privkeyfile)
    RSAcipher = PKCS1_OAEP.new(keypair)
    
    if(hdr[6:8].hex() == "0001"):
        try:
            # decrypt the AES key to get tk using private key
            tk = RSAcipher.decrypt(etk)
        except ValueError:
            print('Error: Decryption of AES key is failed.')
            sys.exit(1)
    else:
        print('Error: Unsupported message type for decryption.')
        sys.exit(1)
    
    # extract nonce (sqn(2) + rnd(6)), MAC, and encrypted payload from the message
    nonce = hdr[6:14]
    mac = mtp_message[-(12 + 256):-256]
    epd = mtp_message[16:-(12 + 256)]
    print("\nExtracted nonce:", nonce.hex())
    print("Extracted MAC:", mac.hex())
    print("Extracted encrypted payload (epd):", epd.hex())
    
    cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=12)
    
    try:
        plaintext = cipher.decrypt_and_verify(epd, mac)
        print("MAC verification successful.")
        print("Plaintext:")
        print(plaintext.decode("utf-8"))
    except ValueError:
        print("MAC verification FAILED.")
    

server_response(mtp_message)
