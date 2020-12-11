import socket
import threading
from Crypto.Cipher import AES
class Server:
    def __init__(self): # Main method
        self.start_server() #Calls start server method

    def start_server(self):
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #Intializing Socket for connection
        key = bytes("a1b2c3d4a1b2c3d4", "utf_8")
        iv = bytes("13579bde13579bde", "utf_8")
        #cipher = AES.new(key, AES.MODE_CBC, iv)

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
            #enc_username = bytes(c.recv(1024).decode("utf-8", errors="ignore"), encoding="utf8") #Recieves a username with a limit of 1024 bytes
            enc_username = c.recv(1024)


            #print(len(enc_username))
            #length = 16 - (len(enc_username) % 16)
            #enc_username += bytes([length]*length)
            dec_cipher = AES.new(key, AES.MODE_CFB, iv)
            dec_username = dec_cipher.decrypt(enc_username)
            username = dec_username.decode('utf8')
            print(username)
            print('New connection. Username: '+str(username))
            self.broadcast('New person joined the room. Username: '+username)
            """
            Puts the username in a list for username lookup and appends them to clients.
            """
            self.username_lookup[c] = username
            self.clients.append(c)
             
            threading.Thread(target=self.handle_client,args=(c,addr,dec_cipher)).start() #Handles clients with threads

    def broadcast(self,msg):
        for connection in self.clients:
            connection.send(msg.encode()) # Allows the message to be seen on the server.

    def handle_client(self,c,addr, dec_cipher):
        while 1:
            try:
                encode_msg = c.recv(1024) #Recieve message in 1024 bytes
            except:
                c.shutdown(socket.SHUT_RDWR)
                self.clients.remove(c)
                
                print(str(self.username_lookup[c])+' left the room.')
                self.broadcast(str(self.username_lookup[c])+' has left the room.')

                break
            print(dec_cipher)
            dec_msg = dec_cipher.decrypt(encode_msg)
            print(dec_msg)
            if dec_msg.decode('utf8') != '':
                print('New message: '+dec_msg.decode('utf-8'))
                for connection in self.clients:
                    if connection != c:
                        connection.send(dec_msg)

server = Server()
