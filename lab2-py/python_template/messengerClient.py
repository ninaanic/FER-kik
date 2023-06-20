#!/usr/bin/env python3

import pickle

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.exceptions import InvalidSignature

import ecdsa

class MessengerClient:
    """ Messenger client klasa

        Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
        prikladnim.
    """

    def __init__(self, username, ca_pub_key):
        """ Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_pub_key     -- javni ključ od CA (certificate authority)
        conns          -- aktivne konekcije s drugim klijentima
        dh_key_pair    -- inicijalni Diffie-Hellman par ključeva iz metode `generate_certificate`
        """

        self.username = username
        self.ca_pub_key = ca_pub_key
        self.conns = {}                 # za svakog klijenta s kojim komuniciramo spremi 2 32-byte Chain Keya for sending and receiving
        self.dh_key_pair = ()           # naš iniciijalni DH Ratchet key pair
        self.dh_key_pair_all = {}       # za svakog klijenta s kojim komuniciramo spremi naš DH key pair 
        self.dh_pub_key = {}            # za svakog klijenta s kojim komuniciramo spremi javni kljuc
        self.root_key = {}              # za svakog klijenta s kojim komuniciramo spremi 32-byte Root Key


    def generate_certificate(self):
        """ Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

        Metoda generira inicijalni Diffie-Hellman par kljuceva; serijalizirani
        javni kljuc se zajedno s imenom klijenta postavlja u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt moze biti proizvoljan (npr.
        dict ili tuple). Za serijalizaciju kljuca mozete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        """

        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()

        self.dh_key_pair = (public_key, private_key) # inicijalni Diffie-Hellman par kljuceva

        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        certificate_object = (serialized_public_key, self.username)

        return certificate_object

    def receive_certificate(self, cert, signature):
        """ Verificira certifikat klijenta i sprema informacije o klijentu (ime
            i javni ključ)

        Argumenti:
        cert      -- certifikacijski objekt
        signature -- digitalni potpis od `cert`

        Metoda prima certifikacijski objekt (koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
        verificira koristeći javni ključ od CA i, ako je verifikacija uspješna,
        sprema informacije o klijentu (ime i javni ključ). Javni ključ od CA je
        spremljen prilikom inicijalizacije objekta.

        """

        try:
            self.ca_pub_key.verify(signature, pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))
            username = cert[1]
            
            deserialized_clients_public_key = load_pem_public_key(cert[0])                              # deserializacija 
            shared_secret = self.dh_key_pair[1].exchange(ec.ECDH(), deserialized_clients_public_key)    # pomoću svog privatnog i klijentovog javnog ključa generiraj shared secret key 
           
            self.conns[username] = [None, None]                                                         # nova konekcija bez definiranih CK
            self.dh_pub_key[username] = deserialized_clients_public_key                                 # sprema informacije o klijentu (ime i javni ključ)
            self.root_key[username] = shared_secret                                                     # spremi inicijlani RK 
            self.dh_key_pair_all[username] = (self.dh_key_pair[0], self.dh_key_pair[1])                 # spremi za ovog klijenta svoje DH kljuceve koje ces koristit 

        except:
            raise(InvalidSignature)
            


    def send_message(self, username, message):
        """ Slanje poruke klijentu

        Argumenti:
        message  -- poruka koju ćemo poslati
        username -- klijent kojem šaljemo poruku `message`

        Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da klijent posjeduje vaš.
        Ako već prije niste komunicirali, uspostavite sesiju tako da generirate
        nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S novim
        `sending` ključem kriptirajte poruku koristeći simetrični kriptosustav
        AES-GCM tako da zaglavlje poruke bude autentificirano.  Ovo znači da u
        zaglavlju poruke trebate proslijediti odgovarajući inicijalizacijski
        vektor.  Zaglavlje treba sadržavati podatke potrebne klijentu da
        derivira novi ključ i dekriptira poruku.  Svaka poruka mora biti
        kriptirana novim `sending` ključem.

        Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.

        """

        # uspostavi konekciju ako vec nismo komunicirali 
        if (self.conns[username][0] == None):

            # generiraj svoje nove DH kljuceve i spremi ih
            private_key = ec.generate_private_key(ec.SECP384R1())
            public_key = private_key.public_key()
            self.dh_key_pair_all[username] = (public_key, private_key) 

            # napravi dh exchange (Alice-Bob dh_out == Bob-Alice dh_out)
            dh_out = self.dh_key_pair_all[username][1].exchange(ec.ECDH(), self.dh_pub_key[username])

            keys = PBKDF2(dh_out, self.root_key[username], 64, count=1000000, hmac_hash_module=SHA512)
            init_chain_key_send = keys[:32]
            next_root_key = keys[32:]

            self.conns[username][0] = init_chain_key_send
            self.root_key[username] = next_root_key      

        # napravi serijalizaciju svog javnog kljuca i takav javni kljuv posalji u headeru
        serialized_public_key = self.dh_key_pair_all[username][0].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # ostalo isto kao lab1
        curr_chain_key_send = self.conns[username][0]

        keys = PBKDF2(curr_chain_key_send, b'123', 64, count=1000000, hmac_hash_module=SHA512)
        next_chain_key_send = keys[:32]
        message_key = keys[32:]

        self.conns[username][0] = next_chain_key_send   # pomak sending lanca 

        cipher = AES.new(message_key, AES.MODE_GCM)     # enkripcija
        nonce = cipher.nonce 
        cipher_text, tag = cipher.encrypt_and_digest(bytes(message, 'UTF-8')) 

        data_to_send = (tag, nonce, cipher_text, serialized_public_key)
        return data_to_send


    def DHRatchet(self, username, new_dh_pub_key):
        # napravi potrebne double ratchet korake 

        #state.DHr = header.dh
        self.dh_pub_key[username] = new_dh_pub_key

        # state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
        deserialized_clients_public_key = load_pem_public_key(new_dh_pub_key) # deserializacija 
        dh_out = self.dh_key_pair_all[username][1].exchange(ec.ECDH(), deserialized_clients_public_key) 
        keys = PBKDF2(dh_out, self.root_key[username], 64, count=1000000, hmac_hash_module=SHA512)
        new_chain_key_rec = keys[:32]
        new_root_key = keys[32:]
        self.conns[username][1] = new_chain_key_rec
        self.root_key[username] = new_root_key

        # state.DHs = GENERATE_DH()
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        self.dh_key_pair_all[username] = (public_key, private_key) # inicijalni Diffie-Hellman par kljuceva

        # state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
        dh_out = self.dh_key_pair_all[username][1].exchange(ec.ECDH(), deserialized_clients_public_key) 
        keys = PBKDF2(dh_out, self.root_key[username], 64, count=1000000, hmac_hash_module=SHA512)
        new_chain_key_send = keys[:32]
        new_root_key = keys[32:]
        self.conns[username][0] = new_chain_key_send
        self.root_key[username] = new_root_key
        

    def receive_message(self, username, message):
        """ Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- klijent koji je poslao poruku

        Metoda prima kriptiranu poruku od klijenta s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da je klijent izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.

        """
        tag = message[0]
        nonce = message[1]
        cipher_text = message[2]
        new_dh_pub_key = message[3]

        if (self.dh_pub_key[username] != new_dh_pub_key):
            MessengerClient.DHRatchet(self, username, new_dh_pub_key)   # pomak root lanca 

        # ostalo isto kao lab1
        curr_chain_key_rec = self.conns[username][1]

        keys = PBKDF2(curr_chain_key_rec, b'123', 64, count=1000000, hmac_hash_module=SHA512)
        next_chain_key_rec = keys[:32]
        message_key = keys[32:]
        
        self.conns[username][1] = next_chain_key_rec                    # pomak receving lanca 

        cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)        # dekripcija 
        plain_text = cipher.decrypt_and_verify(cipher_text, received_mac_tag=tag) 

        return plain_text.decode('utf-8')


def main():
    pass

if __name__ == "__main__":
    main()
