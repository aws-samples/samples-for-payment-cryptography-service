import re
import time
import socket
import binascii
from typing import Tuple

def createRsaKey(atalla_address):
    print("Generating RSA key pair from Atalla using command 120")
    #generate rsa key pair
    data = '<120#w#010001#2048#>'
    response = send_data(atalla_address, data.encode(), '<220#(.*?)#(.*?)#(.*?)#>', b'>') #<220#Public Key#Private Key#Check Digits#[Key slot#]>
    pubKey = response[0]
    privKey = response[1]
    return pubKey,privKey

def sign139(keyReference, message, atalla_address ):
    print("Signing with Atalla using command 139")
    #valjue of 5 means sha-256
    data = '<139#5#1#%s######%s#>' % (binascii.hexlify(message).decode().upper(), keyReference)
    response = send_data(atalla_address, data.encode(), '<239#.*?#(.*?)#.*>', b'>')
    return response[0]

def send_data(target: Tuple[str, int], data: bytes, pattern: str, terminator: bytes = b''):

    s = socket.create_connection(target, timeout=10)
    s.settimeout(30)
    s.sendall(data)

    end_time = time.time() + 30

    output = b''
    while end_time > time.time():
        try:
            output += s.recv(2**16)
            if terminator and terminator in output:
                break
        except socket.timeout:
            break

    matcher = re.match(pattern, output.decode())
    if not matcher:
        raise Exception('Failed to parse data ' + output.decode() + ' for command ' + data.decode())
    return matcher.groups()