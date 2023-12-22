import hashlib
import hmac
import secrets
import socket
import struct
import threading
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


def handle_client(client, address):
    print(f"[NEW CONNECTION] {address} connected.")

    class AESCipher:
        def __init__(self, key):
            self.key = hashlib.sha3_256(key.encode()).digest()

        def encrypt(self, data):
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return b64encode(iv + cipher.encrypt(pad(data.encode(), AES.block_size)))

        def decrypt(self, data):
            raw = b64decode(data)
            cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
            return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode()

    def ECDH(server):
        n2 = secrets.randbelow(curveA.field.n)
        Q2 = n2 * curveA.g
        server.send(AESCipher(PSK).encrypt(hex(Q2.x) + hex(Q2.y)))
        Q1xy = AESCipher(PSK).decrypt(server.recv(1024))
        Q1x = int(Q1xy[:Q1xy.find("0x", 3)], 16)
        Q1y = int(Q1xy[Q1xy.find("0x", 3):], 16)
        Q1 = ec.Point(curve=curveA, x=Q1x, y=Q1y)
        return n2 * Q1

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
                Rn = (self.F1 * ((sLst[-1] - 1) / (rLst[-1] - self.Key.x)) ** 2 - rLst[
                    -1] - self.Key.x) % curveA.field.p
                rLst.append(Rn)
                return Rn

        def getS(self):
            if self.n == 2:
                S2 = (-(self.F2 / 2 * self.F1) * (
                            ((self.F2 ** 2) / (4 * self.F1)) - 3 * self.Key.x) - 1) % curveA.field.p
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

    def HmacSHA3_256(key, mess):
        return hmac.new(key.encode(), mess.encode(), hashlib.sha3_256).digest()

    def SHA3_256(mess):
        hashBytes = hashlib.sha3_256(mess.encode()).digest()
        return int.from_bytes(hashBytes, "big")

    def verify(mess, sign, PK):
        msgHash = SHA3_256(mess)
        IsValid = Generator.Generator.verify(secp256r1_generator, PK, msgHash, sign)
        return IsValid

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

    OTPClient = AESCipher(PSK).decrypt(client.recv(1024))
    if OTPClient == str(OTP):
        notificationOTP = "OTP Authentication success notification"
    else:
        notificationOTP = "OTP Authentication failed notification"
        client.close()
    client.send(AESCipher(PSK).encrypt(notificationOTP))
    # -- OTK --------------------------------------------
    try:
        while True:
            rn = Isogeny(Key, n).getR()
            sn = Isogeny(Key, n).getS()
            zn = XOR(rn, sn)
            OTK = HmacSHA3_256(zn, PSK)[0]
            n += 1
            OTKClient = AESCipher(PSK).decrypt(client.recv(1024))
            if OTKClient == "CLOSE CONNECTION":
                print(f"CONNECTIONED WITH {address} ENDED!")
                client.close()
                break
            else:
                msg = OTKClient[:OTKClient.find("0x")]
                r = OTKClient[OTKClient.find("0x"): OTKClient.rfind('0x')]
                s = OTKClient[OTKClient.rfind('0x'):]
                signature = (int(r, 16), int(s, 16))
                pubKey = OTK * curveA.g
                valid = verify(msg, signature, (pubKey.x, pubKey.y))
                if valid:
                    print(f"{address} >", msg)
                else:
                    print(f"{address} Message Not Valid")
                    print(f"CONNECTIONED WITH {address} ENDED!")
                    client.close()

    except:
        print(f"CONNECTIONED WITH {address} ENDED!")
        client.close()


def main():
    print("[STARTING] Server is starting...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    while True:
        client, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client, address))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


if __name__ == "__main__":
    main()
