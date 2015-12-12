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
from Crypto.Cipher import AES

if len(sys.argv) != 3:
    print "Usage: dec_jpg.py <jpg_file> <key>"
    sys.exit()

# Key is base64 encoded to make copy-paste easier, so decode it
key = base64.b64decode(sys.argv[2])

# Load JPG to memory
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

# 0xFF, 0xFE marks the start of a JPG comment
com = jpg_data.find("\xFF\xFE", soi)
if com < 0:
    print "Failed to find message."
    sys.exit()

# two byte comment length, 16 byte IV, remainder is cipher text
msg_len = struct.unpack('>H', jpg_data[com + 2:com + 4])[0]
iv  = jpg_data[com + 4:com + 20]
msg = jpg_data[com + 20:com + msg_len + 4]

suite = AES.new(key, AES.MODE_CBC, iv)
print suite.decrypt(msg)