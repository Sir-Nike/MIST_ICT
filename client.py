import requests, os, secrets, time
from AES import aes_encrypt, aes_decrypt
from LZW import lzw_compress, lzw_decompress
import timer
import struct

SERVER = "http://127.0.0.1:8000"
key_bytes = secrets.token_bytes(16)

def serialize_codes(codes: list[int]) -> bytes:
    # Pack each code as unsigned short (2 bytes, big endian)
    return b''.join(struct.pack(">H", c) for c in codes)

def deserialize_codes(data: bytes) -> list[int]:
    # Convert bytes back into a list of unsigned shorts
    return [struct.unpack(">H", data[i:i+2])[0] for i in range(0, len(data), 2)]

def upload_file(key):
    path = input("Enter file path: ")
    # 1. Read file
    with open(path, "rb") as f:
        data = f.read()
    # 2. Compress
    print("Compressing file using LZW compression...")
    start_compress = time.perf_counter()    
    compressed = lzw_compress(data)
    compress_time = (time.perf_counter() - start_compress) * 1e6
    print(f"Time taken to compress file: {compress_time:.6f} µs")    
    byte_data = serialize_codes(compressed)
    # 3. Encrypt
    encrypted = aes_encrypt(byte_data, key, 10)
    # 4. Upload
    filename = os.path.basename(path) + ".enc"
    r = requests.post(f"{SERVER}/upload/", files={"file": (filename, encrypted)})
    print("Upload:", r.json())

def download_file(key):
    filename = input("Enter file name: ") + ".enc"
    output_path = input("Enter name of output file: ")
    r = requests.get(f"{SERVER}/download/{filename}")
    resp = r.json()
    if "error" in resp:
        print("Error:", resp["error"])
        return
    encrypted = bytes.fromhex(resp["data"])
    # 1. Decrypt
    decrypted = aes_decrypt(encrypted, key, 10)
    codes = deserialize_codes(decrypted)
    # 2. Decompress
    start_decompress = time.perf_counter()
    plain = lzw_decompress(codes)
    decompress_time = (time.perf_counter() - start_decompress) * 1e6   
    print(f"Time taken to decompress file: {decompress_time:.6f} µs")   
    # 3. Save restored file
    with open(output_path, "wb") as f:
        f.write(plain)
    print(f"Restored {output_path}")

def start_client():
    print("This program compresses files using LZW compression, encrypts it using AES, and uploads the file to a server acting as a mock cloud.")
    while True:
        print("\nEnter u to upload file, d to download file, b for benchmarks, q to quit")
        choice = input("Enter choice: ")
        if choice == "q":
            break
        elif choice == "u":
            upload_file(key_bytes)    
        elif choice == "d":
            download_file(key_bytes)
        elif choice == "b":
            path = input("Enter file path: ")
            with open(path, "rb") as f:
                data = f.read()
            timer.benchmark_aes(data)
        else:
            print("Invalid choice")

