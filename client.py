import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
class Client:
    def __init__(self):  #main method
        self.create_connection()

    def create_connection(self):
        key = bytes("a1b2c3d4a1b2c3d4", "utf_8")
        iv = bytes("13579bde13579bde", "utf_8")
        #cipher = AES.new(key, AES.MODE_CBC,iv)
        cipher= AES.new(key, AES.MODE_CFB, iv)
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # Setting up connection
        
        while 1: #test server connectivity
            try:
                #host = input('Enter host name --> ')
                host = "192.168.0.153"
                print(type(host))
                port = 4444
                #port = int(input('Enter port --> '))
                print(type(port))
                self.s.connect((host,port)) #Connects to server with port number
                
                break
            except:
                print("Couldn't connect to server")

        self.username = input('Enter username --> ')
        name = self.username.encode('utf-8')
        enc_name = cipher.encrypt(name)

        #print(type(self.username.encode()))
        #length = 16 - (len(name) % 16)
        #print(length)
        #name += bytes([length]*length)
        #print(len(name))
        print(enc_name)
        self.s.send(enc_name)# Sends to server
        
        message_handler = threading.Thread(target=self.handle_messages,args=())
        message_handler.start()

        input_handler = threading.Thread(target=self.input_handler,args=(cipher, self.username))
        input_handler.start()

    def handle_messages(self): #Message itself

        while 1:
                print(self.s.recv(1024)) #Input length in bytes

    def input_handler(self,cipher, name): #Username
        while 1:
            msg = name + ' - ' + input("> ")
            #print("flag")
            enc_msg = msg.encode('utf-8')
            encrypt_msg = cipher.encrypt(enc_msg)
            self.s.send(( encrypt_msg)) #Username with "-" identifying the message

client = Client()
