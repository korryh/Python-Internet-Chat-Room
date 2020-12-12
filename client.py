"""
Group 12A
MATH314 001
Professor Lauderdale
12/11/20

"""
import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
class Client:
    def __init__(self):  #main method
        self.create_connection()

    def create_connection(self):
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # Setting up connection
    
        self.key = RSA.generate(2048)
        clientPublicKey = self.key.publickey().export_key()
        self.username = input('Enter username --> ')

        while 1: #test server connectivity
            try:
                host = input('Enter IP Address --> ')

                port = int(input('Enter port --> '))
                self.s.connect((host,port)) #Connects to server with port number
                
                break
            except:
                print("Couldn't connect to server")

        #Receive the server's public key
        self.server_public_key = RSA.import_key(self.s.recv(1024))

        #Send the client public key to the server
        self.s.send(clientPublicKey)

        #Receive the server encrypted aes key
        server_aes_encrypted_key = self.s.recv(1024)
        rsa_dec_cipher = PKCS1_OAEP.new(self.key)
        aes_key_message = rsa_dec_cipher.decrypt(server_aes_encrypted_key).decode('utf8').split('\n')
        aes_key = bytes.fromhex(aes_key_message[0])
        aes_iv = bytes.fromhex(aes_key_message[1])
        aes_cipher = AES.new(aes_key, AES.MODE_CFB, aes_iv)
        decrypt_aes_cipher = AES.new(aes_key, AES.MODE_CFB, aes_iv)

        # Now we send our username to the server
        name = self.username.encode('utf-8')
        enc_name = aes_cipher.encrypt(name)

        # Hash and Sign the username message
        hash_enc_name = SHA256.new(enc_name)
        name_signature = pss.new(self.key).sign(hash_enc_name)
        username_message = (enc_name.hex() + '\n' + name_signature.hex()).encode('utf8')
        self.s.send(username_message) # Sends to server
        
        message_handler = threading.Thread(target=self.handle_messages,args=(decrypt_aes_cipher, None))
        message_handler.start()

        input_handler = threading.Thread(target=self.input_handler,args=(aes_cipher, self.username))
        input_handler.start()

    def handle_messages(self, cipher, throwaway): #Message itself
        while 1:
            msg = self.s.recv(1024).decode('utf8').split('\n')
            enc_msg = bytes.fromhex(msg[0])
            sig = bytes.fromhex(msg[1])
            try:
                verifier = pss.new(self.server_public_key)
                message_hash = SHA256.new(enc_msg)
                verifier.verify(message_hash, sig)
            except (ValueError, TypeError):
                print('HMAC FAILED')
                break
            dec_msg = cipher.decrypt(enc_msg)
            print(dec_msg.decode('utf8')) #Input length in bytes

    def input_handler(self,cipher, name): #Username
        while 1:
            msg = input("> ")
            #print("flag")
            enc_msg = msg.encode('utf-8')
            encrypt_msg = cipher.encrypt(enc_msg)
            sig = pss.new(self.key).sign(SHA256.new(encrypt_msg))
            to_send = (encrypt_msg.hex() + '\n' + sig.hex()).encode('utf8')
            self.s.send(to_send) #Username with "-" identifying the message

client = Client()
