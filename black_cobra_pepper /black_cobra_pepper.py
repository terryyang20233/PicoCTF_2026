# A simple XOR function that doesn't require the 'pwn' library
def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def to_matrix(key_hex):
    bytes_list = [int(key_hex[i:i+2], 16) for i in range(0, 32, 2)]
    array = [[0] * 4 for _ in range(4)]
    for i in range(16):
        array[i % 4][i // 4] = hex(bytes_list[i])[2:]
    return array

def from_matrix(matrix):
    reconstructed = ""
    for col in range(4):
        for row in range(4):
            reconstructed += matrix[row][col].zfill(2)
    return reconstructed

def inv_shift_rows(state):
    # Reverses the left cyclic shifts done by standard AES ShiftRows
    state[1][1], state[1][2], state[1][3], state[1][0] = state[1][0], state[1][1], state[1][2], state[1][3]
    state[2][2], state[2][3], state[2][0], state[2][1] = state[2][0], state[2][1], state[2][2], state[2][3]
    state[3][3], state[3][0], state[3][1], state[3][2] = state[3][0], state[3][1], state[3][2], state[3][3]
    return state

def gmul(a, b):
    if isinstance(b, str): b = int(b, 16)
    if isinstance(a, str): a = int(a, 16)
    p = 0
    for c in range(8):
        if b & 1: p ^= a
        a <<= 1
        if a & 0x100: a ^= 0x11b
        b >>= 1
    return p

def inv_mix_columns(s):
    # Standard AES InvMixColumns multiplication
    ss = [[0] * 4 for _ in range(4)]
    for c in range(4):
        ss[0][c] = hex(gmul(0x0e, s[0][c]) ^ gmul(0x0b, s[1][c]) ^ gmul(0x0d, s[2][c]) ^ gmul(0x09, s[3][c]))[2:].zfill(2)
        ss[1][c] = hex(gmul(0x09, s[0][c]) ^ gmul(0x0e, s[1][c]) ^ gmul(0x0b, s[2][c]) ^ gmul(0x0d, s[3][c]))[2:].zfill(2)
        ss[2][c] = hex(gmul(0x0d, s[0][c]) ^ gmul(0x09, s[1][c]) ^ gmul(0x0e, s[2][c]) ^ gmul(0x0b, s[3][c]))[2:].zfill(2)
        ss[3][c] = hex(gmul(0x0b, s[0][c]) ^ gmul(0x0d, s[1][c]) ^ gmul(0x09, s[2][c]) ^ gmul(0x0e, s[3][c]))[2:].zfill(2)
    for i in range(4):
        for j in range(4):
            s[i][j] = ss[i][j]
    return s

def decrypt_diff(delta_c_hex):
    state = to_matrix(delta_c_hex)
    inv_shift_rows(state)
    for _ in range(9):
        inv_mix_columns(state)
        inv_shift_rows(state)
    return from_matrix(state)

# 1. Given ciphertexts
c1 = "d7481d89f1aaf5a857f56edd2ae8994c"
c2 = "8c7d66558130eb5796d131beb43c9934"

# 2. XOR the ciphertexts to eliminate the key
delta_c = xor_bytes(bytes.fromhex(c1), bytes.fromhex(c2)).hex()

# 3. Apply the inverse unkeyed linear transformation (L^-1)
delta_p = decrypt_diff(delta_c)

# 4. XOR with the known pt1 to recover the Flag
pt1 = "72616e646f6d64617461313131313131"  # "randomdata111111"
flag_bytes = xor_bytes(bytes.fromhex(pt1), bytes.fromhex(delta_p))

print("Flag:", flag_bytes.decode(errors="ignore"))