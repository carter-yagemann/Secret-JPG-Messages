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
import base64
import sys
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if len(sys.argv) != 3:
    sys.stdout.write("Usage: dec_jpg.py <jpg_file> <password>\n")
    sys.exit(1)

backend = default_backend()

jpg_file, password = sys.argv[1:3]

# load JPG
with open(jpg_file, 'rb') as ifile:
    jpg = ifile.read()

# 0xFF, 0xD8 marks the start of a JPG
soi = jpg.find(b"\xFF\xD8")
if soi < 0:
    sys.stderr.write("Failed to find start of image, is this a JPG?\n")
    sys.exit(1)
soi += 2

# 0xFF, 0xFE marks the start of a JPG comment
com = jpg.find(b"\xFF\xFE", soi)
if com < 0:
    sys.stderr.write("Failed to find message.\n")
    sys.exit(1)

# two byte comment length, 16 byte IV, 16 byte salt, remainder is ciphertext
msg_len    = struct.unpack('>H', jpg[com + 2:com + 4])[0]
iv         = jpg[com + 4:com + 20]
salt       = jpg[com + 20:com + 36]
ciphertext = jpg[com + 36:com + msg_len + 4]

# key stretching
kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend)

key = kdf.derive(password.encode('utf8'))

# decrypt and remove padding
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
decryptor = cipher.decryptor()
msg_padded = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = padding.PKCS7(256).unpadder()
msg = unpadder.update(msg_padded) + unpadder.finalize()

sys.stdout.write(msg.decode('utf8') + "\n")
