import time
import hashlib
import argon2
import bcrypt
from Crypto.Cipher import AES, ChaCha20, Blowfish, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import scrypt as scrypt_kdf
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
import pandas as pd
import math


#function for padding for block ciphers
def pad(data, block_size):
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

#AES-GCM Encryption
def aes_gcm_encrypt(data, key):
    iv = get_random_bytes(12)  #nonce is 12 bytes
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, iv, tag

def aes_gcm_decrypt(ciphertext, key, iv, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

#AES-CBC Encryption
def aes_cbc_encrypt(data, key):
    iv = get_random_bytes(16)  #IV is 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext, iv

def aes_cbc_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    return unpad(plaintext_padded)

#ChaCha20 Encryption
def chacha20_encrypt(data, key):
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    return ciphertext, nonce

def chacha20_decrypt(ciphertext, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)

#Blowfish Encryption
def blowfish_encrypt(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, Blowfish.block_size))
    return ciphertext, cipher.iv

def blowfish_decrypt(ciphertext, key, iv):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    return unpad(plaintext_padded)

#Triple DES (3DES) Encryption
def triple_des_encrypt(data, key):
    cipher = DES3.new(key, DES3.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, DES3.block_size))
    return ciphertext, cipher.iv

def triple_des_decrypt(ciphertext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    return unpad(plaintext_padded)

#RSA Encryption for Hybrid Encryption
def rsa_encrypt_key(symmetric_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(symmetric_key)
    return encrypted_key

def rsa_decrypt_key(encrypted_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    symmetric_key = cipher_rsa.decrypt(encrypted_key)
    return symmetric_key

#Hybrid RSA + AES Encryption
def hybrid_rsa_aes_encrypt(data, rsa_keypair):
    symmetric_key = get_random_bytes(32)  # AES-256 key
    encrypted_key = rsa_encrypt_key(symmetric_key, rsa_keypair.publickey())

    #Encrypt the data with AES-GCM using the symmetric key
    ciphertext, iv, tag = aes_gcm_encrypt(data, symmetric_key)

    return encrypted_key, ciphertext, iv, tag

def hybrid_rsa_aes_decrypt(encrypted_key, ciphertext, iv, tag, rsa_keypair):
    symmetric_key = rsa_decrypt_key(encrypted_key, rsa_keypair)

    #Decrypt the data with AES-GCM using the symmetric key
    return aes_gcm_decrypt(ciphertext, symmetric_key, iv, tag)


#Argon2 Hashing
def argon2_hash(password):
    ph = argon2.PasswordHasher()
    return ph.hash(password)

def argon2_verify(hashed_password, password):
    ph = argon2.PasswordHasher()
    try:
        return ph.verify(hashed_password, password)
    except argon2.exceptions.VerifyMismatchError:
        return False

#bcrypt Hashing
def bcrypt_hash(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def bcrypt_verify(hashed_password, password):
    return bcrypt.checkpw(password.encode(), hashed_password)

#PBKDF2 Hashing
def pbkdf2_hash(password, salt=None):
    if not salt:
        salt = get_random_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key, salt

def pbkdf2_verify(hashed_password, password, salt):
    rederived_key, _ = pbkdf2_hash(password, salt)
    return rederived_key == hashed_password

#scrypt Hashing
def scrypt_hash(password, salt=None):
    if not salt:
        salt = get_random_bytes(16)
    key = scrypt_kdf(password.encode(), salt, 32, N=2**14, r=8, p=1)
    return key, salt

def scrypt_verify(hashed_password, password, salt):
    rederived_key, _ = scrypt_hash(password, salt)
    return rederived_key == hashed_password

"""# SHA-256 Hashing
def sha256_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

# SHA-3-256 Hashing
def sha3_256_hash(password):
    return hashlib.sha3_256(password.encode()).hexdigest()
"""
#rounding function
def round_sig(x, sig=3):
    if x == 0:
        return 0
    else:
        digits = sig - int(math.floor(math.log10(abs(x)))) - 1
        return round(x, digits)
    
#Benchmark for the encryption algorithms
def benchmark_encryption(algorithm_name, encrypt_func, decrypt_func, key, data):
    start_time = time.time()
    if algorithm_name == 'RSA+AES':
        encrypted_key, ciphertext, iv, tag = encrypt_func(data, key)
    else:
        ciphertext, *extra = encrypt_func(data, key)
    encryption_time = time.time() - start_time
    encryption_time = round_sig(encryption_time)

    start_time = time.time()
    if algorithm_name == 'RSA+AES':
        plaintext = decrypt_func(encrypted_key, ciphertext, iv, tag, key)
    else:
        plaintext = decrypt_func(ciphertext, key, *extra)
    decryption_time = time.time() - start_time
    decryption_time = round_sig(decryption_time)

    assert plaintext == data, f"{algorithm_name} decryption failed!"

    return encryption_time, decryption_time

#Benchmark for the password hashing algorithms
def benchmark_hashing(algorithm_name, hash_func, verify_func=None, password='mypassword'):
    start_time = time.time()
    if algorithm_name in ['PBKDF2', 'scrypt']:
        hashed_password, salt = hash_func(password)
    else:
        hashed_password = hash_func(password)

    hashing_time = time.time() - start_time
    hashing_time = round_sig(hashing_time)

    if verify_func:
        start_time = time.time()
        if algorithm_name in ['PBKDF2', 'scrypt']:
            is_valid = verify_func(hashed_password, password, salt)
        else:
            is_valid = verify_func(hashed_password, password)
        verification_time = time.time() - start_time if is_valid else None
    else:
        verification_time = None
    
    verification_time = round_sig(verification_time)

    return hashing_time, verification_time

#Vizualization
def plot_times_for_each_algorithm(results, algorithm_name):
    fig, ax = plt.subplots(figsize=(10, 6))
    data_sizes = [result['data_size'] for result in results]
    enc_times = [result['encryption'] for result in results]
    dec_times = [result['decryption'] for result in results]
    
    ax.plot(data_sizes, enc_times, label=f'{algorithm_name} Encryption', marker='o', color='blue')
    ax.plot(data_sizes, dec_times, label=f'{algorithm_name} Decryption', marker='o', color='green')
    
    ax.set_title(f'{algorithm_name} Encryption and Decryption Times')
    ax.set_xlabel('Data Size (bytes)')
    ax.set_ylabel('Time (seconds)')
    plt.xticks(rotation=45)
    ax.legend()
    plt.tight_layout()
    plt.show()

def plot_final_comparison(algorithm_results, data_size, time_key, title):
    fig, ax = plt.subplots(figsize=(10, 6))
    algorithms = list(algorithm_results.keys())
    times = [algorithm_results[algo][-1][time_key] for algo in algorithms]  #Get the times for the 1GB data size

    ax.bar(algorithms, times, color='purple')
    ax.set_title(f'{title} for all Algorithms at {data_size} bytes')
    ax.set_ylabel('Time (seconds)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def plot_hashing_times(hashing_results):
    fig, ax = plt.subplots(figsize=(10, 6))
    algorithms = list(hashing_results.keys())
    hash_times = [hashing_results[algo]['hashing'] for algo in algorithms]
    ax.bar(algorithms, hash_times, color='orange')
    ax.set_title('Password Hashing Time Comparison')
    ax.set_ylabel('Time (seconds)')
    ax.set_xlabel('Hashing Algorithms')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def plot_verification_times(hashing_results):
    fig, ax = plt.subplots(figsize=(10, 6))
    algorithms = list(hashing_results.keys())
    ver_times = [hashing_results[algo]['verification'] if hashing_results[algo]['verification'] is not None else 0 for algo in algorithms]
    ax.bar(algorithms, ver_times, color='red')
    ax.set_title('Password Verification Time Comparison')
    ax.set_ylabel('Time (seconds)')
    ax.set_xlabel('Hashing Algorithms')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    #Test encryption with larger data sizes, up to 100GB
    data_sizes = [1024 , #1KB
                  1024 * 1024 , #1MB
                  10 * 1024 * 1024, #10MB
                  100 * 1024 * 1024, #100MB
                  1024 * 1024 * 1024, #1GB
                  #10 * 1024 * 1024 * 1024, #10GB
                  #100 * 1024 * 1024 * 1024, #100GB
                  #1024 * 1024 * 1024 * 1024 #1TB
                  ] 

    encryption_algorithms = {
        'AES-GCM': (aes_gcm_encrypt, aes_gcm_decrypt, 32),        #256-bit key
        'AES-CBC': (aes_cbc_encrypt, aes_cbc_decrypt, 32),        #256-bit key
        'ChaCha20': (chacha20_encrypt, chacha20_decrypt, 32),     #256-bit key
        'Blowfish': (blowfish_encrypt, blowfish_decrypt, 16),     #128-bit key
        'Triple DES': (triple_des_encrypt, triple_des_decrypt, 24), #192-bit key
        'RSA+AES': (hybrid_rsa_aes_encrypt, hybrid_rsa_aes_decrypt, 2048)  #Hybrid RSA+AES
    }
    #results for each algorithm
    algorithm_results = {algorithm: [] for algorithm in encryption_algorithms.keys()}

    hashing_algorithms = {
    'Argon2': (argon2_hash, argon2_verify),
    'bcrypt': (bcrypt_hash, bcrypt_verify),
    'PBKDF2': (pbkdf2_hash, pbkdf2_verify),
    'scrypt': (scrypt_hash, scrypt_verify),
    #'SHA-256': (sha256_hash, None),
    #'SHA-3-256': (sha3_256_hash, None)
    }

    hashing_results = {}
    for name, (hash_func, verify_func) in hashing_algorithms.items():
        hash_time, verify_time = benchmark_hashing(name, hash_func, verify_func)
        hashing_results[name] = {'hashing': hash_time, 'verification': verify_time}
    
    hashing_result = pd.DataFrame.from_dict(hashing_results, orient='index')
    print(hashing_result)

    #benchmarking for each data size
    algorithmResults = []
    for size in data_sizes:
        data = get_random_bytes(size)
        print(f"\nBenchmarking with data size: {size} bytes")

        for name, (encrypt_func, decrypt_func, key_size) in encryption_algorithms.items():
            if name == 'RSA+AES':
                key = RSA.generate(key_size)
            else:
                key = get_random_bytes(key_size)
            enc_time, dec_time = benchmark_encryption(name, encrypt_func, decrypt_func, key, data)
            algorithm_results[name].append({'data_size': size, 'encryption': enc_time, 'decryption': dec_time})
            algorithmResults.append({
                'Algorithm' : name,
                'Data Size(bytes)': size,
                'Encryption Time(sec)': enc_time,
                'Decryption Time(sec)': dec_time
            })
    
    algorithmResults = pd.DataFrame(algorithmResults)
    print(algorithmResults)

    #print(algorithm_results)
    #esult = pd.DataFrame(algorithm_results)        
    #print(result)
    #Plotting
    for name, results in algorithm_results.items():
        plot_times_for_each_algorithm(results, name)

    #Final Comparison of all algorithms at 1GB data size
    plot_final_comparison(algorithm_results, data_size=10 * 1024 * 1024 * 1024, time_key='encryption', title='Encryption Time Comparison')
    plot_final_comparison(algorithm_results, data_size=10 * 1024 * 1024 * 1024, time_key='decryption', title='Decryption Time Comparison')
    plot_hashing_times(hashing_results)
    plot_verification_times(hashing_results)