import os
import pickle
import hashlib
import binascii
import multiprocessing
import requests
from ellipticcurve.privateKey import PrivateKey
from time import time, sleep

DATABASE = r'database/MAR_23_2019/'
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1304138813316010014/lBExLXHZeiNO1BM-ZnP_pcaD1t35qQSiS3--xD54D0tvA-WDqX1EiWSNZ7s4hlz3qf3n"

def send_discord_notification(message):
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
        if response.status_code != 204:
            print(f"Failed to send Discord notification: {response.status_code}, {response.text}")
    except:
        pass  # Suppress errors for Discord notifications.

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key):
    pk = PrivateKey().fromString(bytes.fromhex(private_key))
    return '04' + pk.publicKey().toString().hex().upper()

def public_key_to_address(public_key):
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count): output.append(alphabet[0])
    return ''.join(output[::-1])

def private_key_to_WIF(private_key):
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]): value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = alphabet[mod] + result, div
    result = alphabet[value] + result
    for c in var:
        if c == 0: pad += 1
        else: break
    return alphabet[0] * pad + result

def process(private_key, public_key, address, database, match_counter):
    if address in database[0] or \
       address in database[1] or \
       address in database[2] or \
       address in database[3]:
        WIF_key = private_key_to_WIF(private_key)
        with open('plutus.txt', 'a') as file:
            file.write(f"hex private key: {private_key}\n"
                       f"WIF private key: {WIF_key}\n"
                       f"public key: {public_key}\n"
                       f"address: {address}\n\n")
        message = (f"Match Found!\n"
                   f"Address: {address}\n"
                   f"Private Key: {private_key}\n"
                   f"WIF: {WIF_key}")
        send_discord_notification(message)
        match_counter.value += 1  # Update match count

def main(database, match_counter, total_keys_processed):
    start_time = time()
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)
        process(private_key, public_key, address, database, match_counter)
        
        # Update keys processed
        total_keys_processed.value += 1
        
        # Display periodic stats
        if total_keys_processed.value % 100000 == 0:
            elapsed = time() - start_time
            keys_per_second = total_keys_processed.value / elapsed
            print(f"Keys processed: {total_keys_processed.value}, Matches found: {match_counter.value}, Speed: {keys_per_second:.2f} keys/sec")

if __name__ == '__main__':
    try:
        database = [set() for _ in range(4)]
        count = len(os.listdir(DATABASE))
        half = count // 2
        quarter = half // 2
        print(f"Loading database with {count} files...")
        for c, p in enumerate(os.listdir(DATABASE)):
            print(f'\rReading database: {c + 1}/{count}', end=' ')
            with open(DATABASE + p, 'rb') as file:
                if c < half:
                    if c < quarter: database[0] = database[0] | pickle.load(file)
                    else: database[1] = database[1] | pickle.load(file)
                else:
                    if c < half + quarter: database[2] = database[2] | pickle.load(file)
                    else: database[3] = database[3] | pickle.load(file)
        print(f'\nDatabase loaded successfully! Total addresses: {sum(len(i) for i in database)}')

        # Shared counters for multiprocessing
        match_counter = multiprocessing.Value('i', 0)
        total_keys_processed = multiprocessing.Value('i', 0)

        # Start processes
        processes = []
        for _ in range(multiprocessing.cpu_count()):
            p = multiprocessing.Process(target=main, args=(database, match_counter, total_keys_processed))
            p.start()
            processes.append(p)

        # Monitor matches periodically
        while any(p.is_alive() for p in processes):
            print(f"Matches found: {match_counter.value}, Total keys processed: {total_keys_processed.value}")
            sleep(10)  # Update every 10 seconds

        # Ensure all processes have completed
        for p in processes:
            p.join()

    except Exception as e:
        print(f"Error in main program: {e}")
