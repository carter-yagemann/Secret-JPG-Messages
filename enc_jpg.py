#!/usr/bin/env python
"""
    Copyright (C) 2015 Carter Yagemann

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
"""
import os
import sys
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if len(sys.argv) != 4:
    sys.stdout.write("Usage: enc_jpg.py <jpg_file> <password> <message>\n")
    sys.exit(1)

jpg_file, password, msg = sys.argv[1:4]

# crypto backend
backend = default_backend()

# generate IV, salt
iv   = os.urandom(16)
salt = os.urandom(16)

# key stretching
kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend)

key = kdf.derive(password.encode('utf8'))

# message padding
padder = padding.PKCS7(256).padder()
msg_padded = padder.update(msg.encode('utf8'))
msg_padded += padder.finalize()

# encrypt message
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(msg_padded) + encryptor.finalize()

# load JPG into memory
with open(jpg_file, 'rb') as ifile:
    jpg = ifile.read()

# 0xFF, 0xD8 marks the start of a JPG
soi = jpg.find(b"\xFF\xD8")
if soi < 0:
    sys.stderr.write("Failed to find start of image, is this a JPG?\n")
    sys.exit(1)
soi += 2

# JPG comment: 0xFF, 0xFE, two bytes (big-endian) comment length, comment
jpg_comment = b"\xFF\xFE" + struct.pack('>H', len(ciphertext) + 32) + iv + salt + ciphertext
# insert comment into JPG and write
jpg = jpg[:soi] + jpg_comment + jpg[soi:]
with open(jpg_file, 'wb') as ofile:
    ofile.write(jpg)
