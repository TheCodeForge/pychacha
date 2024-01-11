import hashlib
import os
import secrets
import time

class ChaChaDecryptionError(Exception):
    pass

class ChaCha():

    def __init__(self, key=None, rounds=10):

        #runs chacha unit test on startup
        #self.test()

        if key is None:
            #print("Generating random key")
            self.key=int(secrets.token_hex(32),16)
        elif isinstance(key, str):
            if len(key)==66 and key.startswith("0x"):
                self.key=int(key, 0)
            elif len(key)==64:
                self.key=int(key, 16)
            else:
                h=hashlib.new("sha256")
                h.update(bytearray(key, "utf-8"))
                self.key=int(h.hexdigest(),16)
        elif isinstance(key, int):
            self.key=key & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        else:
            raise ValueError("key must be int or hex string (0x prefix optional)")

        self.rounds=rounds


    @property
    def nonce(self):

        return secrets.randbits(96)

    @property
    def key(self):
        return hex(self.__dict__['key'])

    @key.setter
    def key(self, value):
        self.__dict__['key']=value

    def rotate(self, b, k):

        return ((b<<k) | (b>>(32-k))) & 0xFFFFFFFF

    def QR(self, a, b, c, d):

        a = a+b & 0xFFFFFFFF
        d ^= a
        d = self.rotate(d, 16)

        c = c+d & 0xFFFFFFFF
        b ^= c
        b = self.rotate(b, 12)

        a = a+b & 0xFFFFFFFF
        d ^= a
        d = self.rotate(d, 8)

        c = c+d & 0xFFFFFFFF
        b ^= c
        b = self.rotate(b, 7)

        return a, b, c, d

    def column_round(self, state):
        state[0], state[4], state[8],  state[12] = self.QR(state[0], state[4], state[8],  state[12])
        state[1], state[5], state[9],  state[13] = self.QR(state[1], state[5], state[9],  state[13])
        state[2], state[6], state[10], state[14] = self.QR(state[2], state[6], state[10], state[14])
        state[3], state[7], state[11], state[15] = self.QR(state[3], state[7], state[11], state[15])
        return state

    def diag_round(self, state):
        state[0], state[5], state[10], state[15] = self.QR(state[0], state[5], state[10], state[15])
        state[1], state[6], state[11], state[12] = self.QR(state[1], state[6], state[11], state[12])
        state[2], state[7], state[8],  state[13] = self.QR(state[2], state[7], state[8],  state[13])
        state[3], state[4], state[9],  state[14] = self.QR(state[3], state[4], state[9],  state[14])
        return state

    def keychunk(self, key, bytelen=32):

        #this function also switches endian modes

        bytelist=[]

        while key:
            chunkval = key & 0xFF
            bytelist = [chunkval] + bytelist
            key >>= 8

        #left pad if needed
        while len(bytelist)<bytelen:
            bytelist = [0]+bytelist
        
        output=[]
        for i in range(len(bytelist)//4):
            output.append(self.bits_concat(*tuple(bytelist[-1-4*i:-5-4*i:-1])))
            
        output.reverse()
        return output

    def noncechunk(self, nonce):

        #this function also switches endian modes

        bytelist=[]

        while nonce:
            chunkval = nonce & 0xFF
            bytelist = [chunkval] + bytelist
            nonce >>= 8

        #left pad if needed
        while len(bytelist)<12:
            bytelist = [0]+bytelist
        
        output=[]
        for i in range(len(bytelist)//4):
            output.append(self.bits_concat(*tuple(bytelist[-1-4*i:-5-4*i:-1])))
            
        output.reverse()
        return output

    def bits_concat(self, *args, bitlen=8):

        if any([x>2**bitlen-1 for x in args]):
            raise ValueError(f"A bit argument is too large for concatination with {bitlen}-bit numbers")

        out=0

        for arg in args:
            out <<= bitlen
            out |= arg

        return out


    def chacha_stream(self, nonce, key=None, pos=1):

        key=key or self.__dict__['key']

        #break key to little endian 4 byte chunks
        keywords=self.keychunk(key)

        constants = [bytearray(x,'ascii') for x in ["expa","nd 3","2-by","te k"]]
        for l in constants:
            l.reverse()
        constants=[self.bits_concat(*tuple(x)) for x in constants]

        nonce=self.noncechunk(nonce)

        while pos < 0xFFFFFFFF:
            init_state=[
                constants[0],   constants[1],   constants[2],   constants[3],
                keywords[0],    keywords[1],    keywords[2],    keywords[3],
                keywords[4],    keywords[5],    keywords[6],    keywords[7],
                pos,            nonce[0],       nonce[1],       nonce[2]
                ]
            state=[x for x in init_state]
            
            #rounds
            for i in range(self.rounds):
                state=self.diag_round(self.column_round(state))

            #bitwise addition mod 2^32

            for i in range(16):
                chunk=(state[i]+init_state[i]) & 0xFFFFFFFF
                
                while chunk:
                    yield chunk & 0xFF
                    chunk >>= 8

            pos+=1

    def base36encode(self, number, alphabet='0123456789abcdefghijklmnopqrstuvwxyz'):
        """Converts an integer to a base36 string."""
        if not isinstance(number, int):
            raise TypeError('number must be an integer')

        base36 = ''
        sign = ''

        if number < 0:
            sign = '-'
            number = -number

        if 0 <= number < len(alphabet):
            return sign + alphabet[number]

        while number != 0:
            number, i = divmod(number, len(alphabet))
            base36 = alphabet[i] + base36

        return sign + base36
        
    def encrypt(self, data, nonce=None):

        nonce = nonce or self.nonce
        stream=self.chacha_stream(nonce)

        output=[]
        plainbytes=list(bytearray(data, "utf-8"))
        for plainbyte in plainbytes:
            cypherbyte= plainbyte ^ next(stream)
            output.append(cypherbyte)


        #return hex(self.bits_concat(*tuple(output)))

        output=hex(self.bits_concat(*tuple(output)))
        #left pad
        if len(output)%2:
            output="0x0"+output[2:]
        
        return ':'.join([hex(nonce),output])
        #return bytearray(output).decode('utf-16')

    def crypto_stream(self, nonce=None):

        # if isinstance(nonce, bytes):
        #     nonce=self.bits_concat(*nonce)
        # el

        if isinstance(nonce, int):
            nonce=nonce
        elif not nonce:
            nonce=self.nonce
        else:
            raise ValueError("bad nonce value, must be bytes or int")

        stream=self.chacha_stream(nonce)

        bytes_ = yield list(nonce.to_bytes(12,"big"))
            
        while True:
            cryptobytes=[]
            plainbytes=list(bytes_)
            for byte in plainbytes:
                cryptobytes.append(byte ^ next(stream))
                
            bytes_ = yield cryptobytes
        

    def encrypt_file(self, f):
        
        
        with open(f, "br+") as file:


            file.seek(0)

            stream=self.crypto_stream()
            noncebytes=next(stream)

            sha = hashlib.new('sha512')

            file.seek(0)
            chunk=file.read(64)
            while chunk:
                chunksize=len(chunk)
                sha.update(bytearray(chunk))
                cryptext=stream.send(chunk)
                file.seek(-1*chunksize, 1)
                file.write(bytearray(cryptext))
                chunk=file.read(64)

            digest=sha.digest()
            file.write(bytearray(noncebytes))
            file.write(bytearray(digest))
        return True


    def decrypt_file(self, f):
        
        with open(f, "br+") as file:

            #extract nonce and verification bytes from end of file first
            file.seek(-76, 2)
            pos=file.tell()
            noncebytes=file.read(12)
            nonce=int.from_bytes(noncebytes)
            hash_chunk=file.read(64)

            file.seek(pos)
            file.truncate()
            

            stream=self.crypto_stream(nonce=nonce)
            noncereturn=next(stream)

            sha = hashlib.new('sha512')
            file.seek(0)

            
            chunk=file.read(64)

            output=[]
            while chunk:
                chunksize=len(chunk)
                plainbytes = stream.send(chunk)
                sha.update(bytearray(plainbytes))
                output.append(plainbytes)
                chunk=file.read(64)

            if hash_chunk==sha.digest():
                file.seek(0)
                for chunk in output:
                    file.write(bytearray(chunk))

            else:
                file.seek(pos)
                file.write(bytearray(noncebytes))
                file.write(bytearray(hash_chunk))
                print("Wrong key")
                return False

        return True

    def decrypt(self, data, key=None):

        key=key or self.__dict__['key']

        data=data.split(":")
        nonce=int(data[0], 0)
        cyphertext=int(data[1], 0)
        
        cypherbytes=[]
        while cyphertext:
            cypherbytes = [cyphertext&0xFF]+cypherbytes
            cyphertext>>=8
        stream=self.chacha_stream(nonce, key=key)
        output=[]
        for cypherbyte in cypherbytes:
            plainbyte= cypherbyte^next(stream)
            output.append(plainbyte)

        try:
            return bytearray(output).decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Incorrect key or nonce")

    def encrypt_folder(self, path):

        nothing=True
        for root, dirs, files in os.walk(path):

            nothing=False

            for filename in files:
                name=os.path.join(root, filename)

                try:
                    self.encrypt_file(name)
                    print(f"encrypted {name}")
                except PermissionError:
                    print(f"unable to encrypt {name} due to permissions")

        if nothing:
            return "empty"

        return True

    def decrypt_folder(self, path):

        for root, dirs, files in os.walk(path):

            for filename in files:
                name=os.path.join(root, filename)
                try:
                    x=self.decrypt_file(name)
                    print(f"decrypted {name}")
                except PermissionError:
                    print(f"unable to decrypt {name} due to permissions")
                if not x:
                    return False
        return True
    

    def test(self):

        #test vectors comes straight from RFC 8439

        #2.1.1 Test ChaCha Quarter Round
        a, b, c, d = 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567
        assert self.QR(a,b,c,d) == (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)


        #2.4.2 Test Cypher
        _key=self.__dict__['key']
        self.key=0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

        nonce=0x000000000000004a00000000

        plaintext="Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

        self.rounds=10

        cypher = self.encrypt(plaintext, nonce=nonce)
        expected = "0x4a00000000:0x6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
 
        assert cypher==expected

        decrypted = self.decrypt(cypher)

        assert decrypted==plaintext

        self.key=_key