import time, secrets
import numpy as np
from LZW import *
from AES import *

# ---- timing storage ----
enc_timings = {
    "SubBytes": [],
    "ShiftRows": [],
    "MixColumns": [],
    "AddRoundKey": []
}
dec_timings = {
    "InvSubBytes": [],
    "InvShiftRows": [],
    "InvMixColumns": [],
    "AddRoundKey": []
}

def timed(store, label, func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    elapsed = (end - start) * 1e6  # µs
    store[label].append(elapsed)
    return result

# ---- AES encryption (profiled) ----
def encrypt_block_profiled(plain16, key16, nr=10):
    round_keys = key_expand_128(key16, nr)
    state = bytes_to_state(plain16)

    state = timed(enc_timings, "AddRoundKey", add_round_key, state, round_keys[0])

    for r in range(1, nr):
        state = timed(enc_timings, "SubBytes", sub_bytes, state)
        state = timed(enc_timings, "ShiftRows", shift_rows, state)
        state = timed(enc_timings, "MixColumns", mix_columns, state)
        state = timed(enc_timings, "AddRoundKey", add_round_key, state, round_keys[r])

    state = timed(enc_timings, "SubBytes", sub_bytes, state)
    state = timed(enc_timings, "ShiftRows", shift_rows, state)
    state = timed(enc_timings, "AddRoundKey", add_round_key, state, round_keys[nr])

    return state_to_bytes(state)

def aes_encrypt_profiled(data, key, nr=10, print_block_timings=False):
    data = pkcs7_pad(data, 16)
    ciphertext = b""
    block_timings = []

    for i in range(0, len(data), 16):
        block = data[i:i+16]
        start = time.perf_counter()
        ct_block = encrypt_block_profiled(block, key, nr)
        end = time.perf_counter()
        block_timings.append((end - start) * 1e6)
        ciphertext += ct_block
    
    if print_block_timings == True:
        for i, t in enumerate(block_timings):
            print(f"Enc Block {i} total: {t:.2f} µs")

    return ciphertext

# ---- AES decryption (profiled) ----
def decrypt_block_profiled(cipher16, key16, nr=10):
    round_keys = key_expand_128(key16, nr)
    state = bytes_to_state(cipher16)

    state = timed(dec_timings, "AddRoundKey", add_round_key, state, round_keys[nr])
    state = timed(dec_timings, "InvShiftRows", inv_shift_rows, state)
    state = timed(dec_timings, "InvSubBytes", inv_sub_bytes, state)

    for r in range(nr - 1, 0, -1):
        state = timed(dec_timings, "AddRoundKey", add_round_key, state, round_keys[r])
        state = timed(dec_timings, "InvMixColumns", inv_mix_columns, state)
        state = timed(dec_timings, "InvShiftRows", inv_shift_rows, state)
        state = timed(dec_timings, "InvSubBytes", inv_sub_bytes, state)

    state = timed(dec_timings, "AddRoundKey", add_round_key, state, round_keys[0])
    return state_to_bytes(state)

def aes_decrypt_profiled(data, key, nr=10, print_block_timings=False):
    plaintext = b""
    block_timings = []

    for i in range(0, len(data), 16):
        block = data[i:i+16]
        start = time.perf_counter()
        pt_block = decrypt_block_profiled(block, key, nr)
        end = time.perf_counter()
        block_timings.append((end - start) * 1e6)
        plaintext += pt_block

    if print_block_timings == True:
        for i, t in enumerate(block_timings):
            print(f"Dec Block {i} total: {t:.2f} µs")

    return pkcs7_unpad(plaintext)

# ---- Statistics ----
def print_stats():
    print("\n=== AES Encryption Profiling ===")
    for step, values in enc_timings.items():
        if values:
            print(f"{step:12s} | avg {np.mean(values):.2f} µs | "
                  f"min {np.min(values):.2f} µs | max {np.max(values):.2f} µs")

    print("\n=== AES Decryption Profiling ===")
    for step, values in dec_timings.items():
        if values:
            print(f"{step:12s} | avg {np.mean(values):.2f} µs | "
                  f"min {np.min(values):.2f} µs | max {np.max(values):.2f} µs")

def benchmark_aes(data):
    key = secrets.token_bytes(16)

    ct = aes_encrypt_profiled(data, key)
    pt = aes_decrypt_profiled(ct, key)

    print_stats()