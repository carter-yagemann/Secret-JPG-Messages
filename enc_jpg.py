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
import os
import sys
import struct
from Crypto.Cipher import AES

if len(sys.argv) != 3:
    print "Usage: enc_jpg.py <jpg_file> <message>"
    sys.exit()

# Generate IV and key
try:
    key = os.urandom(32)
    iv  = os.urandom(16)
except NotImplementedError:
    print "Failed to generate random key."
    sys.exit()
print "Key:", base64.b64encode(key)

# Pad plain text with spaces because AES-CBC needs 16 byte blocks
plain_text = sys.argv[2] + (" " * (16 - (len(sys.argv[2]) % 16)))

# Encrypt plain text
suite = AES.new(key, AES.MODE_CBC, iv)
cipher_text = suite.encrypt(plain_text)

# Load JPG into memory
try:
    jpg_file = open(sys.argv[1], "rb")
    jpg_data = jpg_file.read()
    jpg_file.close()
except:
    print "Failed to load image file."
    sys.exit()

# 0xFF, 0xD8 marks the start of a JPG
soi = jpg_data.find("\xFF\xD8")
if soi < 0:
    print "Failed to find start of image, is this a JPG?"
    sys.exit()

# JPG comment: 0xFF, 0xFE, two bytes (big-endian) comment length, comment
msg = "\xFF\xFE" + struct.pack('>H', len(cipher_text) + 16) + iv + cipher_text
# Insert comment into JPG
jpg_data = jpg_data[:soi + 2] + msg + jpg_data[2 + soi:]

# Write to file
try:
    jpg_file = open(sys.argv[1], "wb")
    jpg_file.write(jpg_data)
    jpg_file.close()
except:
    print "Failed to write message to image file."
    sys.exit()