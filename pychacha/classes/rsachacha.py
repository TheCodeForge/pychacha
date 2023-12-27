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