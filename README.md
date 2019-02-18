# scrypt algorithm
#
### Description
An implementation of scrypt password-based key derivation function algorithm in python. It will return a derived key of length dkLen bytes. Both Chacha and Salsa20 are implemented and available in the code.

Parameters of the algorithm explained:
 - passphrase: a string of characters to be hashed
 - salt: chosen salt, protection against rainbow table attacks
 - N: CPU/memory cost parameter
 - p: parallelization parameter
 - r: blocksize parameter (is set to 8)
 - dkLen: desired key length in bytes


### Usage Example
```
> python scrypt_alg.py
```
```
Password:
parolatare
Salt:
saredemare
p:
8
N:
12
dk_len (preferred key length):
256
```

```
> b'$pbkdf2-sha256$29000$w7vDsiBQTS7CmsKWCcKJXXFGwqrCviRJGAXCoELDtV42w7QSw6HCrTLDl8OIOcKWw6VYVcKswrPCviXDiMKqwpXDtMOhwonCriXDn3nCgMKicsKzYsKiGMOoD8KPwpFCwovCqQtCbsOSwpdMExguwpVQIMO3w43DlDHCscKSS8KNwrgIUVEhFiJfw7VlLVHDrsKLF8OdwpzCrVcXH8OeFcOTOSVjZMKpRynDu0/Dt8O'
```


### Documentation

https://tools.ietf.org/html/rfc7914

http://www.tarsnap.com/scrypt/scrypt.pdf

https://en.wikipedia.org/wiki/Scrypt

https://en.wikipedia.org/wiki/Salsa20
