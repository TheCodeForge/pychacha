import time
import secrets
import hashlib
import os
import getpass
import rsa

class ChaChaDecryptionError(Exception):
    pass

class ChaCha():

    def __init__(self, key=None):

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

    @property
    def nonce(self):
        return int(time.time()*10**7)

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

        nonce=self.keychunk(nonce, bytelen=12)

        while pos < 0xFFFFFFFF:
            init_state=[
                constants[0],   constants[1],   constants[2],   constants[3],
                keywords[0],    keywords[1],    keywords[2],    keywords[3],
                keywords[4],    keywords[5],    keywords[6],    keywords[7],
                pos,            nonce[0],       nonce[1],       nonce[2]
                ]
            state=[x for x in init_state]
            
            #rounds
            for i in range(10):
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
        
    def encrypt(self, data):

        nonce=self.nonce
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

        if isinstance(nonce, bytes):
            nonce=self.bits_concat(*nonce)
        elif isinstance(nonce, int):
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
            hash_chunk=file.read(64)

            file.seek(pos)
            file.truncate()
            

            stream=self.crypto_stream(nonce=noncebytes)
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
                self.encrypt_file(name)

        if nothing:
            return "empty"

        return True

    def decrypt_folder(self, path):

        for root, dirs, files in os.walk(path):

            for filename in files:
                name=os.path.join(root, filename)
                x=self.decrypt_file(name)
                if not x:
                    return False
        return True

class RSAchacha():

    def __init__(self, rsakey=None):

        if not rsakey:

            self.pub, self.priv = rsa.newkeys(512)

        elif isinstance(rsakey, rsa.PrivateKey):

            self.priv=rsakey

            self.pub = rsa.PublicKey(self.priv.n, self.priv.e)

        elif isinstance(rsakey, rsa.PublicKey):

            self.priv = None
            self.pub = rsakey

        else:
            raise TypeError("`rsakey` must be an instance of rsa.PublicKey or rsa.PrivateKey or None.")


    def encrypt_file(self, f, priv=None, pub=None):

        chacha=ChaCha()

        priv = priv or self.priv
        pub = pub or self.pub

        with open(f, "br+") as file:

            file.seek(0)

            stream = chacha.crypto_stream()
            
            noncebytes=next(stream)

            file.seek(0)
            
            chunk=file.read(64)

            output=[]
            
            while chunk:
                
                chunksize=len(chunk)
                cryptext=stream.send(chunk)
                output.append(bytearray(cryptext))
                chunk=file.read(64)

            file.seek(0)
            sig = rsa.sign(file.read(), priv, 'SHA-256')

            file.seek(0)
            for x in output:
                file.write(x)
            
            file.write(bytearray(noncebytes))
            file.write(bytearray(sig))

            encrypted_key = encrypted_key = rsa.core.encrypt_int(chacha.__dict__['key'], pub.e, pub.n)
            file.write(bytearray(encrypted_key.to_bytes(64, 'big')))

    def decrypt_file(self, f, priv=None, pub=None):

        priv=priv or self.priv

        pub = pub or self.pub

        if not priv:

            raise ValueError("Cannot decrypt without private key")
        
        with open(f, "br+") as file:

            #extract nonce and verification bytes from end of file first
            file.seek(-140, 2)
            pos=file.tell()
            
            noncebytes=file.read(12)
            sig_chunk=file.read(64)
            key_chunk = file.read(64)

            key=rsa.core.decrypt_int(int.from_bytes(key_chunk, "big"), priv.d, priv.n)

            

            file.seek(pos)
            file.truncate()

            chacha = ChaCha(key)

            stream=chacha.crypto_stream(nonce=noncebytes)
            noncereturn=next(stream)

            file.seek(0)

            
            chunk=file.read(64)

            output=[]
            while chunk:
                chunksize=len(chunk)
                plainbytes = stream.send(chunk)
                output.append(bytearray(plainbytes))
                chunk=file.read(64)

            try:
                rsa.verify(b"".join(output), sig_chunk, pub)
            except rsa.pkcs1.VerificationError:
                print("Signiture verification failed")
                file.seek(pos)
                file.write(bytearray(noncebytes))
                file.write(bytearray(sig_chunk))
                file.write(bytearray(key_chunk))
                return False

            file.seek(0)
            for x in output:
                file.write(x)

        return True
    
    def encrypt(self, data, pub=None):

        chacha = ChaCha()

        pub = pub or self.pub


        encrypted_key = rsa.core.encrypt_int(chacha.__dict__['key'], pub.e, pub.n)

        return f"{hex(encrypted_key)}:{chacha.encrypt(data)}"

    def decrypt(self, data, priv=None):

        priv = priv or self.priv

        if not self.priv:

            raise ValueError("Cannot decrypt without private key")

        data=data.split(":", maxsplit=1)

        encrypted_key = data[0]
        data=data[1]


        encrypted_key = int(encrypted_key.split("0x")[1], 16)

        chacha_key = rsa.core.decrypt_int(encrypted_key, priv.d, priv.n)

        return ChaCha(key=chacha_key).decrypt(data)

        




def main():

    os.chdir(os.path.expanduser('~'))

    key=True
    key2=False
    while key!=key2:
        key=getpass.getpass("Key: ")
        key2=getpass.getpass("Confirm Key: ")

    c=ChaCha(key)

    del key
    del key2

    def change_key(x):
        h=hashlib.new("sha256")
        h.update(bytearray(x, "utf-8"))
        c.key=int(h.hexdigest(),16)
        return True

    functions={
        ('encrypt','file'):c.encrypt_file,
        ('decrypt','file'):c.decrypt_file,
        ('encrypt','folder'):c.encrypt_folder,
        ('decrypt','folder'):c.decrypt_folder,
        ('encrypt','text'):c.encrypt,
        ('decrypt','text'):c.decrypt,
        ('set','key'):change_key
        }

    while True:
        try:
            command=input("> ")
            tokens=command.split(maxsplit=2)

            print(functions[tuple(tokens[0:2])](tokens[2]))
                
        except Exception as e:
            print(e)
            continue





if __name__=="__main__":
     main()
