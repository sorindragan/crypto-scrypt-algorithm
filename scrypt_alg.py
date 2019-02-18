import itertools
import hashlib
import hmac
import struct
import sys

from copy import deepcopy
from Crypto.Hash import HMAC
from passlib.hash import pbkdf2_sha256

def apply_hmac(password, update_string):
    secret = password
    h = HMAC.new(secret)
    h.update(update_string)

    return h.hexdigest()

def apply_pbkdf2(input, key_length, salt):
    hash = b''

    while len(hash) < key_length:
        pbkdf2sha256 = bytes(pbkdf2_sha256.encrypt(input, salt = salt), "utf8")
        hash += pbkdf2sha256

    return hash[:key_length]

def QR(a, b, c, d):
    ROTL = lambda a, b: (a << b) | (a >> (32 - b))
    a += b
    d ^= a
    d = ROTL(d,16)
    c += d
    b ^= c
    b = ROTL(b,12)
    a += b
    d ^= a
    d = ROTL(d, 8)
    c += d
    b ^= c
    b = ROTL(b, 7)
    return a, b, c, d

def chacha(B):
    x = deepcopy(B)
    for i in range(0, 20, 2):
        x[0], x[4], x[ 8], x[12] = QR(x[0], x[4], x[ 8], x[12])
        x[1], x[5], x[ 9], x[13] = QR(x[1], x[5], x[ 9], x[13])
        x[2], x[6], x[10], x[14] = QR(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = QR(x[3], x[7], x[11], x[15])
        x[0], x[5], x[10], x[15] = QR(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = QR(x[1], x[6], x[11], x[12])
        x[2], x[7], x[ 8], x[13] = QR(x[2], x[7], x[ 8], x[13])
        x[3], x[4], x[ 9], x[14] = QR(x[3], x[4], x[ 9], x[14])

    return [a + b for a, b in zip(x, B)]

def salsa20(B):
    R = lambda a, b: (a << b) | (a >> (32 - b))

    x = deepcopy(B)
    for i in range(8, 0, -2):
        x[ 4] ^= R(x[ 0] + x[12], 7)
        x[ 8] ^= R(x[ 4] + x[ 0], 9)
        x[12] ^= R(x[ 8] + x[ 4],13)
        x[ 0] ^= R(x[12] + x[ 8],18)
        x[ 9] ^= R(x[ 5] + x[ 1], 7)
        x[13] ^= R(x[ 9] + x[ 5], 9)
        x[ 1] ^= R(x[13] + x[ 9],13)
        x[ 5] ^= R(x[ 1] + x[13],18)
        x[14] ^= R(x[10] + x[ 6], 7)
        x[ 2] ^= R(x[14] + x[10], 9)
        x[ 6] ^= R(x[ 2] + x[14],13)
        x[10] ^= R(x[ 6] + x[ 2],18)
        x[ 3] ^= R(x[15] + x[11], 7)
        x[ 7] ^= R(x[ 3] + x[15], 9)
        x[11] ^= R(x[ 7] + x[ 3],13)
        x[15] ^= R(x[11] + x[ 7],18)
        x[ 1] ^= R(x[ 0] + x[ 3], 7)
        x[ 2] ^= R(x[ 1] + x[ 0], 9)
        x[ 3] ^= R(x[ 2] + x[ 1],13)
        x[ 0] ^= R(x[ 3] + x[ 2],18)
        x[ 6] ^= R(x[ 5] + x[ 4], 7)
        x[ 7] ^= R(x[ 6] + x[ 5], 9)
        x[ 4] ^= R(x[ 7] + x[ 6],13)
        x[ 5] ^= R(x[ 4] + x[ 7],18)
        x[11] ^= R(x[10] + x[ 9], 7)
        x[ 8] ^= R(x[11] + x[10], 9)
        x[ 9] ^= R(x[ 8] + x[11],13)
        x[10] ^= R(x[ 9] + x[ 8],18)
        x[12] ^= R(x[15] + x[14], 7)
        x[13] ^= R(x[12] + x[15], 9)
        x[14] ^= R(x[13] + x[12],13)
        x[15] ^= R(x[14] + x[13],18)

    return [a + b for a, b in zip(x, B)]

def block_mix(B, r):
    X = B[(2 * r - 1) * 16:]
    Y = [0] * (2 * r)

    for i in range(2 * r):
        T = [a ^ b for a, b in zip(X, B[i * 16 : (i + 1) * 16])]
        X = chacha(T)
        Y[i] = X

    evens = [Y[i] for i in range(0, 2 * r, 2)]
    odds = [Y[i] for i in range(1, 2 * r + 1, 2)]

    return list(itertools.chain.from_iterable(evens + odds))

def integerify(pbkdf2_out):
    #treats the input as little endian and converts it to integers
    B = list(pbkdf2_out)
    B = [((B[i + 3] << 24) | (B[i + 2] << 16) | (B[i + 1] << 8) | B[i + 0]) for i in range(0, len(B), 4)]

    return B

def smix(r, B, N):
    X = deepcopy(B)
    V = [0] * N

    for i in range(N):
        V[i] = X
        X = block_mix(X, r)

    for i in range(N):
        j = X[-1] % N
        T = [a ^ b for a, b in zip(X, V[j])]
        X = block_mix(T, r)

    return X

def apply_scrypt(password, salt, update_string, p, r, N, dk_len):
    #HMAC
    hmac_out = apply_hmac(password, update_string)

    #PBKDF2
    pbkdf2_out = integerify(apply_pbkdf2(hmac_out, r * 128 * p, salt=salt))
    
    #SMIX
    B = [0] * p;
    for i in range(p):
        sz = int(len(pbkdf2_out) / p)
        B[i] = smix(r, pbkdf2_out[i * sz : (i + 1) * sz], N)

    B = list(itertools.chain.from_iterable(B))

    #conversion of integers to little endian representated bytes
    Bc = []
    for i in B:
        Bc.append((i >> 0) & 0xff)
        Bc.append((i >> 8) & 0xff)
        Bc.append((i >> 16) & 0xff)
        Bc.append((i >> 24) & 0xff)

    str = ''.join(chr(x) for x in Bc)
    str = bytes(str[:1023], "utf8")
    #PBKDF2
    return apply_pbkdf2(str, dk_len, salt=str[:1023])

def main():
    print("Password:")
    password = sys.stdin.readline()
    password = bytes(password, "utf8")
    print("Salt:")
    salt = sys.stdin.readline()
    salt = bytes(salt, "utf8")
    print("p:")
    p = sys.stdin.readline()
    print("N:")
    N = sys.stdin.readline()
    print("dk_len (preferred key length):")
    dk_len = sys.stdin.readline()
    cipher = apply_scrypt(password, salt, b'update string', int(p), 8, int(N), int(dk_len))
    print(cipher)

if __name__ == '__main__':
    main()
