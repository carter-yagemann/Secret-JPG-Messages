Introduction
============

These Python scripts let you insert encrypted messages into JPG images and later retrieve them.

Technical Overview
==================

The encryption is done using AES 256 in CBC mode. The key is randomly generated using Python's urandom method and outputted into the console. It's up to the user to figure out how to get that key to the receiver securely. IV's are also randomly generated using Python's urandom method.

The cipher text is embedded into the start of the JPG as a comment. Read the encrypting script if you're curious about the file format.

Installation
============

These scripts are written for Python 2.7. The only library dependency is `pycrypto`. You can install it using pip and the included `requirements.txt` file:

    pip install -r requirements.txt

Usage
=====

To add an encrypted message to the image file, use the encryption script:

    python enc_jpg.py image.jpg “My secret message.”

This script will output the key as a base64 encoded string. The receiver needs this key in order to decrypt the message.

To decrypt the message, use the decryption script:

    python dec_jpg.py image.jpg “Hb3lBC3P8bBmrDd1W203wTxV9ZoBQm48ol//nuBfQB8=”
