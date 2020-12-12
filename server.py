"""
Group 12A
MATH314 001
Professor Lauderdale
12/11/20

"""

import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class Server:
    def __init__(self): # Main method
        self.start_server() #Calls start server method

    def start_server(self):
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #Intializing Socket for connection

        self.key = RSA.generate(2048)
        serverPublicKey = self.key.publickey().export_key()

        host = socket.gethostbyname(socket.gethostname()) #Gets the ip address of the host PC
        #port = int(input('Enter port to run the server on --> '))
        port = 4444

        self.clients = []#Creates a list of clients, upcapped.

        self.s.bind((host,port)) #uses ip address and port to connect to the server
        self.s.listen(500) # listen for 500 seconds
    
        print('Running on host: '+str(host))
        print('Running on port: '+str(port))

        self.username_lookup = {} #Creates a list of usernames to lookup

        while 1:
            c, addr = self.s.accept() #Waits for connection to accept
            """
            c.recv(1024).decode spits errors when vanilla, ignore errors and decode in utf8
            cipher only works when it is in a 16 byte boundary. Pad it to fit.
            """
            # Once a client connects, send them the servers public key
            c.send(serverPublicKey)

            # The client should then send us the their public key
            client_public_key = RSA.import_key(c.recv(1024))

            # Generate an AES key and IV
            aes_key = get_random_bytes(16)
            aes_iv = get_random_bytes(16)
            aes_cipher = AES.new(aes_key, AES.MODE_CFB, aes_iv)
            encrypt_aes_cipher = AES.new(aes_key, AES.MODE_CFB, aes_iv)
            # Package the AES key and IV
            message = aes_key.hex() + '\n' + aes_iv.hex()
            message_bytes = bytes(message, "utf_8")

            # encryp the message using the clients public key
            cipher_rsa = PKCS1_OAEP.new(client_public_key)
            enc_aes_key = cipher_rsa.encrypt(message_bytes)

            # send encrypted aes key to the client
            c.send(enc_aes_key)

            # recieve the username from the client
            enc_signed_username_message = c.recv(1024).decode('utf8').split('\n')
            message = bytes.fromhex(enc_signed_username_message[0])
            sig = bytes.fromhex(enc_signed_username_message[1])
            enc_signed_username_hash = SHA256.new(message)
            verifier = pss.new(client_public_key)
            try:
                verifier.verify(enc_signed_username_hash, sig)
            except (ValueError, TypeError):
                print('HMAC failed')
                break
            
            dec_username = aes_cipher.decrypt(message).decode('utf8')
            """
            Puts the username in a list for username lookup and appends them to clients.
            """
            self.username_lookup[c] = dec_username
            self.clients.append((c, encrypt_aes_cipher))

            print(f'New connection. Username: {dec_username}')
            self.broadcast(f'New person joined the room. Username: {dec_username}')
            
            threading.Thread(target=self.handle_client,args=(c,aes_cipher,verifier,dec_username)).start() #Handles clients with threads

    def broadcast(self,msg):
        for (connection, cipher) in self.clients:
            enc_msg = cipher.encrypt(msg.encode('utf8'))
            sig = pss.new(self.key).sign(SHA256.new(enc_msg))
            to_send = (enc_msg.hex() + '\n' + sig.hex()).encode('utf8')
            connection.send(to_send) # Allows the message to be seen on the server.

    def handle_client(self,c,dec_cipher,verifier,username):
        while 1:
            try:
                encode_msg = c.recv(1024).decode('utf8').split('\n') #Recieve message in 1024 bytes
                enc_message = bytes.fromhex(encode_msg[0])
                message_sig = bytes.fromhex(encode_msg[1])
            except:
                c.shutdown(socket.SHUT_RDWR)
                self.clients.remove(c)
                
                print(str(self.username_lookup[c])+' left the room.')
                self.broadcast(str(self.username_lookup[c])+' has left the room.')
                break
            message_hash = SHA256.new(enc_message)
            try:
                verifier.verify(message_hash, message_sig)
            except (ValueError, TypeError):
                print('HMAC failed')
                break
            
            message = dec_cipher.decrypt(enc_message).decode('utf8')
            to_send = f'{username} - {message}'
            print(f'New Message: {to_send}')
            self.broadcast(to_send)

server = Server()
