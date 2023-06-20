#!/usr/bin/env python3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Cipher import AES


class MessengerClient:
    """ Messenger client class

        Feel free to modify the attributes and add new ones as you
        see fit.

    """



    def __init__(self, username, max_skip=10):
        """ Initializes a client

        Arguments:
        username (str) -- client name
        conn (dict) -- Data regarding active connections. 
                        dict u kojem je key username s kojim imamo connetion
                        a value su trenutni send i recv chain key
        max_skip (int) -- Maximum number of message keys that can be skipped in
                          a single chain
        salt -- const koja ide u PBKDF2 funkciju, ista cijelu konekciju ali razlicita za razlicite usere 
                --> a i b cijelu svoju komunikaciju imaju isti salt = salt1
                --> a i c cijelu svoju komunikaciju imaju isti salt = salt2
                --> salt1 != salt2
        Ns -- dict u kojem je key username s kojim imamo connection 
                a value broj poslanih poruka tom usernameu 
        Nr --  dict u kojem je key username s kojim imamo connection 
                a value broj poruka koje smo dobili od tog usernamea 
        MKSKIPPED -- dict of dict 
                        u vanjskom dict key je username s kojim imamo conn a value dict 
                        u unutarnjem dict key je redni broj poruke koja je preskocena a value njezin chain key 

        """

        self.username = username
        self.conn = {}
        self.max_skip = max_skip
        self.salt = get_random_bytes(16)
        self.Ns = {}
        self.Nr = {}
        self.MKSKIPPED = {}


    def add_connection(self, username, chain_key_send, chain_key_recv):
        """ Add a new connection

        Arguments:
        username (str) -- user that we want to talk to
        chain_key_send -- sending chain key (CKs) of the username
        chain_key_recv -- receiving chain key (CKr) of the username

        """
        # 1. dodaju novu conn 
        self.conn[username] = [chain_key_send, chain_key_recv]
        self.Ns[username] = 0
        self.Nr[username] = 0
        self.MKSKIPPED[username] = {}

    
    def send_message(self, username, message):
        """ Send a message to a user

        Get the current sending key of the username, perform a symmetric-ratchet
        step, encrypt the message, update the sending key, return a header and
        a ciphertext.

        Arguments:
        username (str) -- user we want to send a message to
        message (str)  -- plaintext we want to send

        Returns a ciphertext and a header data (you can use a tuple object)

        """

        # 1. Get the current sending key of the username
        curr_chain_key_send = self.conn[username][0]

        # 2. perform a symmetric-ratchet step
            # Calculating the next chain key and message key from a given chain key is 
            # a single ratchet step in the symmetric-key ratchet.
                # state.CKs, mk = KDF_CK(state.CKs)
        keys = PBKDF2(curr_chain_key_send, self.salt, 64, count=1000000, hmac_hash_module=SHA512)
        next_chain_key_send = keys[:32]
        message_key = keys[32:]

        # 3. update the sending key 
        self.conn[username][0] = next_chain_key_send

        # 4. return a header and a ciphertext 
            # header = HEADER(state.DHs, state.PN, state.Ns)
            # state.Ns += 1
            # return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
        cipher = AES.new(message_key, AES.MODE_GCM)
        nonce = cipher.nonce 
        self.Ns[username] += 1 

        cipher_text, tag = cipher.encrypt_and_digest(bytes(message, 'UTF-8')) 

        data_to_send = tuple()
        data_to_send = (self.salt, tag, nonce,  self.Ns[username],  cipher_text)
        return data_to_send


    def try_skipped_message_keys(self, username,  Ns, cipher_text, nonce, tag):
        if Ns in self.MKSKIPPED[username]:
            message_key = self.MKSKIPPED[username][Ns]
            del self.MKSKIPPED[username][Ns]

            cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)
            plain_text = cipher.decrypt_and_verify(cipher_text, received_mac_tag=tag) 

            return plain_text.decode('utf-8')

        else:
            return None

    def skip_message_keys(self, until, username, salt):
        if self.Nr[username] + self.max_skip < until:
            raise Exception

        if self.conn[username][1] != None:
            while self.Nr[username] + 1 < until:
                keys = PBKDF2(self.conn[username][1], salt, 64, count=1000000, hmac_hash_module=SHA512)
                next_chain_key_rec = keys[:32]
                message_key = keys[32:]

                self.conn[username][1] = next_chain_key_rec

                self.MKSKIPPED[username][self.Nr[username]+1] = message_key
                self.Nr[username] += 1


    def receive_message(self, username, message):
        """ Receive a message from a user

        Get the username connection data, check if the message is out-of-order,
        perform necessary symmetric-ratchet steps, decrypt the message and
        return the plaintext.

        Arguments:
        username (str) -- user who sent the message
        message        -- a ciphertext and a header data

        Returns a plaintext (str)

        """

        # 1. Get the username connection data, 
        conn_data = self.conn[username]

        salt = message[0]
        tag = message[1]
        nonce = message[2]
        Ns = message[3]
        cipher_text = message[4]

        # 2. check if the message is out-of-order,
        plain_text = MessengerClient.try_skipped_message_keys(self, username, Ns, cipher_text, nonce, tag)
        if plain_text != None:
            return plain_text
        MessengerClient.skip_message_keys(self, Ns, username, salt)

        # 3. perform necessary symmetric-ratchet steps, 
        keys = PBKDF2(conn_data[1], salt, 64, count=1000000, hmac_hash_module=SHA512)
        next_chain_key_rec = keys[:32]
        message_key = keys[32:]
        
        self.conn[username][1] = next_chain_key_rec
        self.Nr[username] += 1

        # 4. decrypt the message 
        cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)

        # 5. return the plaintext
        plain_text = cipher.decrypt_and_verify(cipher_text, received_mac_tag=tag) 
        return plain_text.decode('utf-8')
