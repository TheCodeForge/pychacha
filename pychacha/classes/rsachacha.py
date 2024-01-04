import rsa
import secrets

from .chacha import ChaCha

class RSAChaCha(ChaCha):

    def __init__(self, rsakey=None, rounds=10):

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

        ChaCha.__init__(self, key=None, rounds=rounds)


    def reroll_key(self):

        self.key=int(secrets.token_hex(32),16)
        self.encrypted_key = rsa.core.encrypt_int(self.__dict__['key'], self.pub.e, self.pub.n)

    def encrypt(self, *args, **kwargs):

        self.reroll_key()

        output = ChaCha.encrypt(self, *args, **kwargs)

        return f"{hex(self.encrypted_key)}:{output}"

    def decrypt(self, data):

        encrypted_key, nonce_and_cypher = data.split(':', maxsplit=1)

        self.key=rsa.core.decrypt_int(int(encrypted_key, 16), self.priv.d, self.priv.n)

        return ChaCha.decrypt(self, nonce_and_cypher)



    def test(self):



        # #test vectors comes straight from RFC 8439

        # #2.1.1 Test ChaCha Quarter Round
        a, b, c, d = 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567
        assert self.QR(a,b,c,d) == (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)

        #fixed rsa key - this was randomly generated and has no significance outside test vector
        _pub, _priv = self.pub, self.priv

        self.pub = rsa.PublicKey(
            9489053008171918004521995711314059285684920438560514661973642968568072229798629559357030553582747788448963660476091084486272572353223479742397055206362341, 
            65537)

        self.priv = rsa.PrivateKey(
            9489053008171918004521995711314059285684920438560514661973642968568072229798629559357030553582747788448963660476091084486272572353223479742397055206362341, 
            65537, 
            6572997534400118431592612406831627163163378444990336513871820038208718353543742101321634197490138199897514178481332926938418769860925536897744477702600445, 
            6167195187831042391390080945549041441452317413513234333348625500405622274387015243, 
            1538633482347937296747458692466267315205847655477592298087628805640473487)

        # #2.4.2 Test Cypher
        self.key=0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        self.encrypted_key = rsa.core.encrypt_int(self.__dict__['key'], self.pub.e, self.pub.n)

        nonce=0x000000000000004a00000000

        plaintext="Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

        self.rounds=10

        output = ChaCha.encrypt(self, plaintext, nonce=nonce)
        cypher = f"{hex(self.encrypted_key)}:{output}"

        expected = "0x8824be95fa814185447c016320e5c5072b2d5765c632e32882ffcca056c6654b59a94b38b904976fc4cf3e23dc081127cb67ee48a62dfef374fd52e78312fc06:0x4a00000000:0x6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"

        assert cypher==expected

        decrypted = self.decrypt(cypher)

        assert decrypted==plaintext

        self.pub, self.priv = _pub, _priv

        self.reroll_key()


    def encrypt_file(self, f):

        self.reroll_key()

        ChaCha.encrypt_file(self, f)

        with open(f, "br+") as file:
            file.seek(0,2)
            file.write(self.encrypted_key.to_bytes(64))

        print(self.key)
        print(self.encrypted_key)
        return True

    def decrypt_file(self, f):

        with open(f, "br+") as file:

            #get encrypted chacha key from end of file
            file.seek(-64, 2)

            self.encrypted_key=int.from_bytes(file.read(64))

            print(self.encrypted_key)

            self.key=rsa.core.decrypt_int(self.encrypted_key, self.priv.d, self.priv.n)

            print(self.key)

            file.seek(-64, 2)
            file.truncate()

        ChaCha.decrypt_file(self, f)