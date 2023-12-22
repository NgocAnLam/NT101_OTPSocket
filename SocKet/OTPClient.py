import hashlib
import hmac
import secrets
import socket
import struct
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from pycoin.ecdsa import Generator
from pycoin.ecdsa.secp256r1 import secp256r1_generator
from tinyec import registry, ec

HOST = '192.168.31.80'
PORT = 9001
PSK = "myPassword"


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print(f"[CONNECTED] Client connected to server at {HOST}:{PORT}")

    class AESCipher:
        def __init__(self, key):
            self.key = hashlib.sha3_256(key.encode('utf8')).digest()

        def encrypt(self, data):
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return b64encode(iv + cipher.encrypt(pad(data.encode(), AES.block_size)))

        def decrypt(self, data):
            raw = b64decode(data)
            cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
            return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode()

    def ECDH(client):
        n1 = secrets.randbelow(curveA.field.n)
        Q1 = n1 * curveA.g
        client.send(AESCipher(PSK).encrypt(hex(Q1.x) + (hex(Q1.y))))
        Q2xy = AESCipher(PSK).decrypt(client.recv(1024))
        Q2x = int(Q2xy[:Q2xy.find("0x", 3)], 16)
        Q2y = int(Q2xy[Q2xy.find("0x", 3):], 16)
        Q2 = ec.Point(curve=curveA, x=Q2x, y=Q2y)
        return n1 * Q2

    class Isogeny:
        def __init__(self, PSKey, count):
            self.Key = PSKey
            self.n = count
            self.F1 = (self.Key.x ** 3 + curveA.a * self.Key.x + curveA.b) % curveA.field.p
            self.F2 = (self.Key.x ** 3 + curveB.a * self.Key.x + curveB.b) % curveB.field.p

        def getR(self):
            if self.n == 2:
                R2 = (((self.F2 ** 2) / (4 * self.F1)) - 2 * self.Key.x) % curveA.field.p
                rLst.append(R2)
                return R2
            else:
                Rn = (self.F1 * ((sLst[-1] - 1) / (rLst[-1] - self.Key.x)) ** 2 - rLst[-1] - self.Key.x) % curveA.field.p
                rLst.append(Rn)
                return Rn

        def getS(self):
            if self.n == 2:
                S2 = (-(self.F2 / 2 * self.F1) * (((self.F2 ** 2) / (4 * self.F1)) - 3 * self.Key.x) - 1) % curveA.field.p
                sLst.append(S2)
                return S2
            else:
                Sn = (-((sLst[-1] - 1) / (rLst[-1] - self.Key.x)) * (rLst[-1] - self.Key.x) - 1) % curveA.field.p
                sLst.append(Sn)
                return Sn

    def XOR(f1, f2):
        rtrn = []
        f1 = struct.pack('d', f1)
        f2 = struct.pack('d', f2)
        for F1, F2 in zip(f1, f2):
            rtrn.append(F1 ^ F2)
        return str(struct.unpack('d', bytes(rtrn))[0])

    def HmacSHA3_256(key, msg):
        return hmac.new(key.encode(), msg.encode(), hashlib.sha3_256).digest()

    def SHA3_256(msg):
        hashBytes = hashlib.sha3_256(msg.encode()).digest()
        return int.from_bytes(hashBytes, "big")

    def sign(msg, privKey):
        msgHash = SHA3_256(msg)
        signMsg = Generator.Generator.sign(secp256r1_generator, privKey, msgHash)
        return signMsg

    curveA = registry.get_curve('secp256r1')
    curveB = registry.get_curve('brainpoolP256r1')
    n = 3
    rLst = [0, 0]
    sLst = [0, 0]
    # -- ECDH --------------------------------------------
    Key = ECDH(client)
    # -- OTP ---------------------------------------------
    r2 = Isogeny(Key, 2).getR()
    s2 = Isogeny(Key, 2).getS()
    z2 = XOR(r2, s2)
    OTP = HmacSHA3_256(z2, PSK)[0]

    client.send(AESCipher(PSK).encrypt(str(OTP)))
    msgOTP = AESCipher(PSK).decrypt(client.recv(1024))
    print(msgOTP)
    # -- OTK ---------------------------------------------
    while True:
        mess = input("> ")
        if mess == "":
            client.send(AESCipher(PSK).encrypt("CLOSE CONNECTION"))
            break
        else:
            rn = Isogeny(Key, n).getR()
            sn = Isogeny(Key, n).getS()
            zn = XOR(rn, sn)
            OTK = HmacSHA3_256(zn, PSK)[0]

            signature = sign(mess, OTK)
            print("\nMessage:", mess)
            client.send(AESCipher(PSK).encrypt(mess + hex(signature[0]) + hex(signature[1])))
            n += 1


if __name__ == "__main__":
    main()
