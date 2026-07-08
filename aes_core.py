# AES-128 Core Implementation with Step-by-Step Logging

# S-Box
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# Inverse S-Box
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Round constants
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def xtime(a):
    """Multiply by 2 in GF(2^8)"""
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff

def gmul(a, b):
    """Multiply two bytes in GF(2^8)"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def bytes_to_state(data):
    """Convert 16 bytes to 4x4 column-major state matrix"""
    s = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            s[r][c] = data[r + 4*c]
    return s

def state_to_bytes(s):
    """Convert 4x4 state matrix to 16 bytes (column-major)"""
    out = []
    for c in range(4):
        for r in range(4):
            out.append(s[r][c])
    return out

def state_to_hex(s):
    """Convert state to list of lists of hex strings"""
    return [[f"{s[r][c]:02x}" for c in range(4)] for r in range(4)]

def rot_word(w):
    return w[1:] + w[:1]

def sub_word(w):
    return [SBOX[b] for b in w]

def key_expansion(key_bytes):
    """Expand 16-byte key into 11 round keys, with detailed steps"""
    steps = []
    w = []
    
    # Initial key state
    init_state = bytes_to_state(key_bytes)
    steps.append({
        "type": "key_init",
        "label": "Initial Key State",
        "state": state_to_hex(init_state)
    })
    
    # W[0..3] from key
    for i in range(4):
        word = [key_bytes[4*i], key_bytes[4*i+1], key_bytes[4*i+2], key_bytes[4*i+3]]
        w.append(word)
        steps.append({
            "type": "word_init",
            "label": f"W[{i}]",
            "word": [f"{b:02x}" for b in word],
            "note": f"Diambil langsung dari kunci"
        })
    
    # Generate W[4..43]
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            rw = rot_word(temp)
            sw = sub_word(rw)
            rc = RCON[i // 4]
            xored = [sw[0] ^ rc, sw[1], sw[2], sw[3]]
            g_steps = {
                "rot_word": [f"{b:02x}" for b in rw],
                "sub_word": [f"{b:02x}" for b in sw],
                "rcon": f"{rc:02x}",
                "after_xor_rcon": [f"{b:02x}" for b in xored],
            }
            new_word = [xored[j] ^ w[i-4][j] for j in range(4)]
            steps.append({
                "type": "word_g",
                "label": f"W[{i}]",
                "g_steps": g_steps,
                "w_prev4": [f"{b:02x}" for b in w[i-4]],
                "result": [f"{b:02x}" for b in new_word],
                "note": f"W[{i}] = g(W[{i-1}]) ⊕ W[{i-4}]"
            })
        else:
            new_word = [temp[j] ^ w[i-4][j] for j in range(4)]
            steps.append({
                "type": "word_xor",
                "label": f"W[{i}]",
                "w_prev1": [f"{b:02x}" for b in temp],
                "w_prev4": [f"{b:02x}" for b in w[i-4]],
                "result": [f"{b:02x}" for b in new_word],
                "note": f"W[{i}] = W[{i-1}] ⊕ W[{i-4}]"
            })
        w.append(new_word)
    
    # Build round keys as 4x4 matrices
    round_keys_raw = []
    round_key_states = []
    for rnd in range(11):
        rk = []
        for col in range(4):
            rk.extend(w[rnd*4 + col])
        round_keys_raw.append(rk)
        rk_state = bytes_to_state(rk)
        round_key_states.append(state_to_hex(rk_state))
        steps.append({
            "type": "round_key",
            "label": f"RK{rnd}",
            "round": rnd,
            "state": state_to_hex(rk_state)
        })
    
    return round_keys_raw, round_key_states, steps

def add_round_key(state, rk_bytes):
    rk_state = bytes_to_state(rk_bytes)
    return [[state[r][c] ^ rk_state[r][c] for c in range(4)] for r in range(4)]

def sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def inv_sub_bytes(state):
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def shift_rows(state):
    result = [row[:] for row in state]
    for r in range(1, 4):
        result[r] = state[r][r:] + state[r][:r]
    return result

def inv_shift_rows(state):
    result = [row[:] for row in state]
    for r in range(1, 4):
        result[r] = state[r][4-r:] + state[r][:4-r]
    return result

def mix_columns(state):
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        result[0][c] = gmul(0x02, col[0]) ^ gmul(0x03, col[1]) ^ col[2] ^ col[3]
        result[1][c] = col[0] ^ gmul(0x02, col[1]) ^ gmul(0x03, col[2]) ^ col[3]
        result[2][c] = col[0] ^ col[1] ^ gmul(0x02, col[2]) ^ gmul(0x03, col[3])
        result[3][c] = gmul(0x03, col[0]) ^ col[1] ^ col[2] ^ gmul(0x02, col[3])
    return result

def inv_mix_columns(state):
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        result[0][c] = gmul(0x0e,col[0])^gmul(0x0b,col[1])^gmul(0x0d,col[2])^gmul(0x09,col[3])
        result[1][c] = gmul(0x09,col[0])^gmul(0x0e,col[1])^gmul(0x0b,col[2])^gmul(0x0d,col[3])
        result[2][c] = gmul(0x0d,col[0])^gmul(0x09,col[1])^gmul(0x0e,col[2])^gmul(0x0b,col[3])
        result[3][c] = gmul(0x0b,col[0])^gmul(0x0d,col[1])^gmul(0x09,col[2])^gmul(0x0e,col[3])
    return result

def aes_encrypt(plaintext_bytes, key_bytes):
    """Encrypt with full step-by-step logging"""
    round_keys_raw, round_key_states, key_steps = key_expansion(key_bytes)
    
    enc_steps = []
    state = bytes_to_state(plaintext_bytes)
    
    # Initial round
    enc_steps.append({
        "round": 0,
        "type": "initial",
        "label": "Initial Round",
        "operations": [
            {"op": "plaintext_state", "label": "State Awal (Plaintext)", "after": state_to_hex(state)},
        ]
    })
    state = add_round_key(state, round_keys_raw[0])
    enc_steps[0]["operations"].append({
        "op": "add_round_key",
        "label": "AddRoundKey (RK0)",
        "rk": round_key_states[0],
        "after": state_to_hex(state)
    })
    
    # Rounds 1-9
    for rnd in range(1, 10):
        ops = []
        before_sb = state_to_hex(state)
        state = sub_bytes(state)
        ops.append({"op":"sub_bytes","label":"SubBytes","before":before_sb,"after":state_to_hex(state)})
        
        before_sr = state_to_hex(state)
        state = shift_rows(state)
        ops.append({"op":"shift_rows","label":"ShiftRows","before":before_sr,"after":state_to_hex(state)})
        
        before_mc = state_to_hex(state)
        state = mix_columns(state)
        ops.append({"op":"mix_columns","label":"MixColumns","before":before_mc,"after":state_to_hex(state)})
        
        before_ark = state_to_hex(state)
        state = add_round_key(state, round_keys_raw[rnd])
        ops.append({"op":"add_round_key","label":f"AddRoundKey (RK{rnd})","before":before_ark,"rk":round_key_states[rnd],"after":state_to_hex(state)})
        
        enc_steps.append({"round": rnd, "type": "main", "label": f"Round {rnd}", "operations": ops})
    
    # Round 10 (final)
    ops = []
    before_sb = state_to_hex(state)
    state = sub_bytes(state)
    ops.append({"op":"sub_bytes","label":"SubBytes","before":before_sb,"after":state_to_hex(state)})
    
    before_sr = state_to_hex(state)
    state = shift_rows(state)
    ops.append({"op":"shift_rows","label":"ShiftRows","before":before_sr,"after":state_to_hex(state)})
    
    before_ark = state_to_hex(state)
    state = add_round_key(state, round_keys_raw[10])
    ops.append({"op":"add_round_key","label":"AddRoundKey (RK10)","before":before_ark,"rk":round_key_states[10],"after":state_to_hex(state)})
    
    enc_steps.append({"round": 10, "type": "final", "label": "Round 10 (Final)", "operations": ops})
    
    cipher_bytes = state_to_bytes(state)
    ciphertext_hex = ''.join(f"{b:02x}" for b in cipher_bytes)
    
    return ciphertext_hex, {"key_expansion": key_steps, "encryption": enc_steps, "round_keys": round_key_states}

def aes_decrypt(ciphertext_bytes, key_bytes):
    """Decrypt with full step-by-step logging"""
    round_keys_raw, round_key_states, key_steps = key_expansion(key_bytes)
    
    dec_steps = []
    state = bytes_to_state(ciphertext_bytes)
    
    # Initial: AddRoundKey RK10
    init_ops = [{"op":"ciphertext_state","label":"State Awal (Ciphertext)","after":state_to_hex(state)}]
    state = add_round_key(state, round_keys_raw[10])
    init_ops.append({"op":"add_round_key","label":"AddRoundKey (RK10)","rk":round_key_states[10],"after":state_to_hex(state)})
    dec_steps.append({"round":"init","type":"initial","label":"Initial (AddRoundKey RK10)","operations":init_ops})
    
    # Rounds 9 down to 1
    for rnd in range(9, 0, -1):
        ops = []
        before = state_to_hex(state)
        state = inv_shift_rows(state)
        ops.append({"op":"inv_shift_rows","label":"InvShiftRows","before":before,"after":state_to_hex(state)})
        
        before = state_to_hex(state)
        state = inv_sub_bytes(state)
        ops.append({"op":"inv_sub_bytes","label":"InvSubBytes","before":before,"after":state_to_hex(state)})
        
        before = state_to_hex(state)
        state = add_round_key(state, round_keys_raw[rnd])
        ops.append({"op":"add_round_key","label":f"AddRoundKey (RK{rnd})","before":before,"rk":round_key_states[rnd],"after":state_to_hex(state)})
        
        before = state_to_hex(state)
        state = inv_mix_columns(state)
        ops.append({"op":"inv_mix_columns","label":"InvMixColumns","before":before,"after":state_to_hex(state)})
        
        dec_steps.append({"round":rnd,"type":"main","label":f"Round {rnd} (Inv)","operations":ops})
    
    # Final round 0
    ops = []
    before = state_to_hex(state)
    state = inv_shift_rows(state)
    ops.append({"op":"inv_shift_rows","label":"InvShiftRows","before":before,"after":state_to_hex(state)})
    
    before = state_to_hex(state)
    state = inv_sub_bytes(state)
    ops.append({"op":"inv_sub_bytes","label":"InvSubBytes","before":before,"after":state_to_hex(state)})
    
    before = state_to_hex(state)
    state = add_round_key(state, round_keys_raw[0])
    ops.append({"op":"add_round_key","label":"AddRoundKey (RK0)","before":before,"rk":round_key_states[0],"after":state_to_hex(state)})
    
    dec_steps.append({"round":0,"type":"final","label":"Round 0 (Final)","operations":ops})
    
    plain_bytes = state_to_bytes(state)
    plaintext_hex = ''.join(f"{b:02x}" for b in plain_bytes)
    
    # Try decode as ASCII
    try:
        plaintext_str = bytes(plain_bytes).decode('utf-8').rstrip('\x00')
    except:
        plaintext_str = plaintext_hex
    
    return plaintext_hex, plaintext_str, {"key_expansion": key_steps, "decryption": dec_steps, "round_keys": round_key_states}
