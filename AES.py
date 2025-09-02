import numpy as np
import secrets

# AES uses GF(2^8) arithmathic. GF is called Galios Feild, or basically a finite field. A field is the set where multiplicative inverse exists.
# We use GF(2^8) as we need 1) We want invertibility for inverse row, inverse S box and other operations, so mod 256 will not work,
# 2) We need a look up table for each byte. Since a byte is 8 bits, the total number of bytes possible is 256

# We need a polynomial with degree 8 (we need exactly 256 elements) to build a field of GF(2^8), and the polynomial must be irreducable
# As we need a polynomial to not break down. We mmake m(x) = x^8 + x^4 + x^3 + x + 1 as the function, and all polynomial arithmathic happens
# mod(m(x)). m(x) in binarry is 0b100011011. Each one represents if there is a x power at that position. 0b100011011 in decimal is 283
# and in hex is 0x11B. We will use the hex format as we can understand m(x) muxh better. Here, x^8 = x^4 + x^3 + x + 1 in mod(m(x))

IRRED = np.uint16(0x11B)


# We do not want x^8 terms in our multiplications as 1 byte -> 8 bits which can only represent till x^7. Since we are dealing with 
# single bytes, we need to make sure that if the polynomial (i.e the bits) go beyond degree 7 (8 bits), we XOR with gf2_8 to reduce
# to less than x^8 term.
def gf_xtime(a):
    # we first need to make uint16 (not a necessary step, but we do this because 1. we are working with only Whole numbers 
    # and 2. We are using bytes, and having uint16 makes it more clear that we are dealing with bytes
    a16 = np.uint16(a)
    # left shift operator basically moves the binary number to the left, basiically multiplying the number with 2.
    # you can also think of it is as a(x) * x, where a(x) is the polynomial built from the binary form of a. In other words
    # You are multiplying the function with x
    res = a16 << 1
    # Because we are dealing with GF(2^8) arithmathic, we basically have to reduce it to mod(m(x)) by XORing with the result of the polynomial multiplication
    # if the original a16 is greater than 128 (shifting a16 (a16 >= 128) 1 leftwards makes it 9 bits). This simulates the multiplication in mod (m(x))
    if a16 & 0x80:
        res = res ^ IRRED
    
    #res can still be more than 8 bits, so we need to mask it by truncating the last bit
    return np.uint8(res & 0xFF)

#this function multiplies 2 polynomials (the binary digits) in GF(2^8)
def gf_mul(a, b):
    a16 = np.uint16(a)
    b16 = np.uint16(b)
    res = np.uint16(0)

    #multiplying in the binary way to make sure that we stay in GF(2^8)
    while b16 > 0:
        #when the ith bit of b is 0, multiplication at that positon does not take place
        if b16 & 1:
            res = res ^ a16
        
        # move the binary a to the left one bit, as bi * (a * 2^i) is summed up to get the rsult
        a16 = gf_xtime(a16)
        # move the binary b to the right one bit, as we do the bi part
        b16 = b16 >> 1
    #truncates 2^8 bit position
    return np.uint8(res & 0xFF)

#We essentially do exponentiation by squaring, a efficient method to square values
#What it essentially does is split the exponenet into a product of smaller expoennets with the powers of 2. The ones that occur, we multiply
# the ones that don't, we ignore. That's what happens when we check e & 1
def gf_pow(a, e):
    #since we are repeatdly ultiplying, we set res = 1, the identity element
    res = np.uint8(1)
    #the base of the exponenet is a
    base = a
    while e:
        if e & 1:
            res = gf_mul(res, base)
        #when e is even, we do base * base
        base = gf_mul(base, base)
        e = e >> 1
    return res

def gf_inv(a):
    # There is a property, where every non zero element raised to the feild size -1 is 1. So if we do -2, we get the inverse
    if a == 0:
        return np.uint8(0)
    return gf_pow(a, 254)

# Now, we shall generate the S-box

def rot1_byte(x, n):
    int_x = int(x)
    return np.uint8( 
        ( 
            (int_x << n) # temporarily moves x to 1 bit extra (0 till 8)
            | 
            ( int_x >> ( 8 - n ) )  # the overflowed bits are put in the remaining position

            # by performing OR, we combine the top n bits (now positioned below) and the shifted bits. The n bots from the first operation
            # Is truncated by doing uint8
        )
        & 0xFF
    )

def build_sbox():
    #The S-Box is a lookup table/hashmap for all the possible bytes. In the substitution process, we use the lookup table to substitute the values
    s = np.zeros(256, dtype = np.uint8)
    # For loop to go through every single element in the S-Box
    for i in range(256):
        #Finds the inverse of i in GF(2^8)
        y = gf_inv(np.uint8(i))
        #sets y = inverse of i
        # the inverse in non linear, but it leaves patterns. doing XOR spreads the influencce of each bit across the sbox. Hence why we XOR it
        # With 4 different rotations, and then xor with a constant
        y = y ^ rot1_byte(y, 1) ^ rot1_byte(y, 2) ^ rot1_byte(y, 3) ^ rot1_byte(y, 4) ^ np.uint8(0x63)
        s[i] = y
    return s

# Making the Sbox and the inverse Sbox (Kind of similar to a hashmap)
SBOX = build_sbox()
INV_SBOX = np.zeros_like(SBOX)
for i in range(256):
    INV_SBOX[SBOX[i]] = i


# Now that we have the SBox, We can start writing helper functions for the various transformations that will take plac in AES

#returns the value in SBOX at that index
def sub_bytes(aes_state):
    return SBOX[aes_state]

#returns the index at that value in Sbox / Retruns the value in INV_SBOX at that index
def inv_sub_bytes(aes_state):
    return INV_SBOX[aes_state]

#We shift the rows N times while performing AES
def shift_rows(aes_state):
    out = np.empty_like(aes_state) #It's basically malloc, memory is allocated, but values aren't initialized to 0
    #Now, we will use the roll function to rotate the matrix (0th row 0 rotation, 1st row, 1 rotation, 2nd row, 2 rotations etc.)
    #we use negative number because we want to shift left, but as long as it's the opposite in the inverse function, things will be fine
    for r in range(4):
        out[r] = np.roll(aes_state[r], -r) 
    return out

#It's basically the same as the above one, but u rotate right instead of left
def inv_shift_rows(aes_state):
    out = np.empty_like(aes_state)
    for r in range(4):
        out[r] = np.roll(aes_state[r], r)
    return out


#This is basically a matrix multiplication with the input column, and the mix matrix (this is a known value from before, a 4x4 matrix)
#We cannot do a direct vectorized approach as we have to stay within GF(2^8)
#Each column in the data is multiplied and replaced by the matrix multiplication of the mixcols matrix
#This spreads the influence of the bytes over the whole column, which increases the diffusion


def mix_single_column(col):
    a0, a1, a2, a3 = col
    return np.array([
        gf_mul(a0,2) ^ gf_mul(a1,3) ^ a2 ^ a3,
        a0 ^ gf_mul(a1,2) ^ gf_mul(a2,3) ^ a3,
        a0 ^ a1 ^ gf_mul(a2,2) ^ gf_mul(a3,3),
        gf_mul(a0,3) ^ a1 ^ a2 ^ gf_mul(a3,2)
    ], dtype=np.uint8)

#Its basically the same thing, except you just use a different matrix to get the inverse elements
def inv_mix_single_column(col):
    a0, a1, a2, a3 = col
    return np.array([
        gf_mul(a0,14) ^ gf_mul(a1,11) ^ gf_mul(a2,13) ^ gf_mul(a3,9),
        gf_mul(a0,9)  ^ gf_mul(a1,14) ^ gf_mul(a2,11) ^ gf_mul(a3,13),
        gf_mul(a0,13) ^ gf_mul(a1,9)  ^ gf_mul(a2,14) ^ gf_mul(a3,11),
        gf_mul(a0,11) ^ gf_mul(a1,13) ^ gf_mul(a2,9)  ^ gf_mul(a3,14)
    ], dtype=np.uint8)

# This basically performs the matrix multiplication on each column of the matrix, using the above defined functions.
# The inv function does it with the invmix_cols matrix
def mix_columns(aes_state):
    out = np.empty_like(aes_state)
    for c in range(4):
        out[:,c] = mix_single_column(aes_state[:,c])
    return out

def inv_mix_columns(aes_state):
    out = np.empty_like(aes_state)
    for c in range(4):
        out[:,c] = inv_mix_single_column(aes_state[:,c])
    return out

# We know start the Keying process
# You XOR the current round cipher/plain text with the key
def add_round_key(aes_state, round_key):
    return aes_state ^ round_key

#AES Key expansion starts here

#rcon table ((n, 4), matrix). This calculates the rotation constant for each rotation, everyone being unique to make sure the expanded keys are unique
def rcon_gen(n):
    #creates a 0 matrix of 4x4
    rcon = np.zeros((n,4), dtype=np.uint8)
    #this is doubled every iteration as we need unique keys each rotation
    c = np.uint8(0x01)
    for i in range(n):
        #this stores the constant for the ith round. We just made into matrix format because everythin else is 4x4
        rcon[i,0] = c
        #doubles c in GF(2^8)
        c = gf_xtime(c)
    return rcon

# The actual key expansion. Generating the 44 keys required
def key_expand_128(key16, nr = 10):
    #nk and nb are the block and key sizes. They are the same as this is just a simple demo
    nk, nb= 4, 4
    #We define a matrix that in default case, has 44 rows, 4 columns. This is because we have 4 bytes per word, 44 words when ciphering 
    W = np.zeros((nb*(nr+1),4), dtype=np.uint8)
    #here, the key16 (which of byte type) is converted into a numpy array using the frombuffer function
    key_arr = np.frombuffer(key16, dtype=np.uint8)
    #W[:nk] means from 0 to nk (here nk = 4), you write a 4x4matrix derived from the key_arr, which itself is derived from the input key16 byte
    #This way, the first nk (4) rows of W contain the starting keys
    W[:nk] = key_arr.reshape(nk,4)
    #RCON basically genertes a bunch of rotation constants which is used to rotate the keys
    RCON = rcon_gen(nr)
    for i in range(nk, nb*(nr+1)):#We want to start from the key that has not been generate
        temp = W[i-1].copy()
        if i % nk == 0:
            temp = np.roll(temp, -1) #Rotates the Bytes
            temp = SBOX[temp] #Substitutes the Bytes
            temp ^= RCON[(i//nk)-1] #XOR with the round constant to make sure each round generates different keys
        W[i] = W[i-nk] ^ temp #now, we take the word nk positions befind and XOR it, as it creates more diffusion
    #W contains Nr+1 * nb * 4 words. In the loop, we reshape W into Nr_1, nb, 4 3D matrix, where every 4x4 is the key for the nr_1 round
    round_keys = np.zeros((nr+1,4,nb), dtype=np.uint8)
    for r in range(nr+1):
        for c in range(nb):
            round_keys[r,:,c] = W[nb*r+c]
    return round_keys

#Changes the byte data type into a 4x4 matrix (order F basically means the first index changes the fastest, the Fortran way)
def bytes_to_state(block16):
    arr = np.frombuffer(block16, dtype=np.uint8)
    return arr.reshape((4,4), order='F')

#changes the 4x4 matrix into a np array, which is then converted into byte
def state_to_bytes(aes_state):
    return bytes(aes_state.reshape(16, order='F'))

#Performs ethe AES encryption nr times. We do not do mix columns in the last round
def encrypt_block(plain16, key16, nr = 10):
    round_keys = key_expand_128(key16, nr)
    aes_state = bytes_to_state(plain16)
    aes_state = add_round_key(aes_state, round_keys[0])
    for r in range(1,nr):
        aes_state = sub_bytes(aes_state)
        aes_state = shift_rows(aes_state)
        aes_state = mix_columns(aes_state)
        aes_state = add_round_key(aes_state, round_keys[r])
    aes_state = sub_bytes(aes_state)
    aes_state = shift_rows(aes_state)
    aes_state = add_round_key(aes_state, round_keys[10])
    return state_to_bytes(aes_state)

#decryption of AES nr times. Mix Columns is not done first round
def decrypt_block(cipher16, key16, nr = 10):
    round_keys = key_expand_128(key16, nr)
    aes_state = bytes_to_state(cipher16)
    aes_state = add_round_key(aes_state, round_keys[10])
    aes_state = inv_shift_rows(aes_state)
    aes_state = inv_sub_bytes(aes_state)
    for r in range(nr-1,0,-1):
        aes_state = add_round_key(aes_state, round_keys[r])
        aes_state = inv_mix_columns(aes_state)
        aes_state = inv_shift_rows(aes_state)
        aes_state = inv_sub_bytes(aes_state)
    aes_state = add_round_key(aes_state, round_keys[0])
    return state_to_bytes(aes_state)

#Padding in case the data size is no 16
def pkcs7_pad(data, block_size=16):
    #Creates a pad length of 16 - data length
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

#unpadding after the decrytion
def pkcs7_unpad(data):
    #the length of the data is given in 
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]

#Encryption
def aes_encrypt(data, key, nr = 10):
    data = pkcs7_pad(data, 16)
    #since we are dealing with byte datatype, we use f"""
    ciphertext = b""
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        ct_block = encrypt_block(block, key, nr)
        ciphertext += ct_block
    return ciphertext

#Decryption
def aes_decrypt(ciphertext, key, nr = 10):
    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        pt_block = decrypt_block(block, key, nr)
        plaintext += pt_block
    return pkcs7_unpad(plaintext)