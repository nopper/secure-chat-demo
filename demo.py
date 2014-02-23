import json
import pbkdf2
from srp import _pysrp as srp
import pyelliptic

class AESCipher(object):
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        BS = 16
        return s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 

    def unpad(self, s):
        return s[0:-ord(s[-1])]

    def encrypt(self, raw):
        raw = self.pad(raw)
        iv = pyelliptic.Cipher.gen_IV('aes-256-cfb')
        ctx = pyelliptic.Cipher(self.key, iv, 1, ciphername='aes-256-cfb')
        ciphertext = ctx.update(raw)
        ciphertext += ctx.final()
        return (iv + ciphertext).encode("hex")

    def decrypt(self, enc):
        enc = enc.decode("hex")
        (iv, enc) = enc[:16], enc[16:]
        ctx = pyelliptic.Cipher(self.key, iv, 0, ciphername='aes-256-cfb')
        return self.unpad(ctx.ciphering(enc))

def create_verification_key(user, salt):
    hash_class = user.hash_class
    return srp.long_to_bytes(pow(user.g, srp.gen_x(hash_class, salt, user.I, user.p), user.N))

class User(object):
    def __init__(self, username, password):
        self.username = username
        self.salt = srp.long_to_bytes(srp.get_random(16))

        key = pbkdf2.PBKDF2(password, self.salt).read(64)
        self.authentication_key, self.initialization_key = (key[:32], key[32:])

        self.cipher = AESCipher(self.initialization_key)
        self.ecc_key = pyelliptic.ECC()

        self.keychain = {
            self.username: self.ecc_key.get_pubkey(),
        }

        self.ecc_group_key = {}
        self.group_keys = {}

    def get_srp_user(self):
        username = self.username
        password = self.initialization_key
        return srp.User(username, password)

    def register(self, server):
        assert self.username not in server.users, "%s already registered" % self.username

        salt = self.salt
        user = self.get_srp_user()

        server.users[self.username] = (salt, create_verification_key(user, salt))

    def login(self, server):
        user = self.get_srp_user()
        username, A = user.start_authentication()

        # We send username and A to the server and obtain a challenge
        s, B = server.auth_request(username, A)
        M = user.process_challenge(s, B)

        if M is None:
            raise srp.AuthenticationFailed()

        # Send M to the verifier
        HAMK = server.verify_session(username, M)
        user.verify_session(HAMK)

        if user.authenticated():
            print "Successfully logged in"

            encrypted = self.cipher.encrypt(self.ecc_key.get_pubkey())

            server.store(username, mykey=encrypted)

    def create_group(self, name, users):
        # Now every other user will generate a pub/key pair
        for user in users:
            user.ecc_group_key[name] = pyelliptic.ECC()
            user.group_keys[name] = {
                user.username: user.ecc_group_key[name].get_pubkey()
            }

        for source in users:
            for dest in users:
                if source != dest:
                    source.group_keys[name][dest.username] = dest.ecc_group_key[name].get_pubkey()


    def send_message(self, name, message):
        session_key = pyelliptic.OpenSSL.rand(32)
        ekeys = []

        for username, pubkey in self.group_keys[name].items():
            ecc_key = self.ecc_group_key[name]
            ekeys.append(ecc_key.encrypt(session_key, pubkey).encode('hex'))

        c = AESCipher(session_key)
        emessage = c.encrypt(message)

        encoded = json.dumps({
            'group': name,
            'message': emessage,
            'keys': ekeys,
        })

        return Message(self.username, self.ecc_key.sign(encoded), encoded)

class Message(object):
    def __init__(self, source, signature, encoded):
        self.source = source
        self.signature = signature
        self.encoded = encoded

    def verify(self, user):
        pubkey_source = user.keychain[self.source]
        return pyelliptic.ECC(pubkey=pubkey_source).verify(self.signature, self.encoded)

    def read(self, user):
        decoded = json.loads(self.encoded)
        ecc_key = user.ecc_group_key[decoded['group']]

        for key in decoded['keys']:
            try:
                session_key = ecc_key.decrypt(key.decode('hex'))
                c = AESCipher(session_key)
                print "%s received: %s" % (user.username, c.decrypt(decoded['message']))
                return
            except:
                print "Trying next key"


class Server(object):
    def __init__(self):
        self.users = {}
        self.verifiers = {}
        self.storage = {}

    def auth_request(self, username, A):
        salt, vkey = self.users[username]

        verifier = srp.Verifier(username, salt, vkey, A)
        s, B = verifier.get_challenge()

        self.verifiers[username] = verifier

        return s, B

    def verify_session(self, username, M):
        HAMK = self.verifiers[username].verify_session(M)

        if HAMK is None:
            raise srp.AuthenticationFailed()

        return HAMK

    def store(self, username, **kwargs):
        self.storage[username] = kwargs
        print "Stored %s for %s" % (', '.join(kwargs.keys()), username)

if __name__ == "__main__":
    server = Server()

    alice = User("Alice", "hello")
    alice.register(server)
    alice.login(server)

    bob = User("Bob", "hello")
    bob.register(server)
    bob.login(server)

    alice.create_group('#lmv', (alice, bob))
    message = alice.send_message('#lmv', 'Hello there')

