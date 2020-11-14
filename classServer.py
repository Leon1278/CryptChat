import socket, getpass, sys
from threading import Thread
from encryptor import AesEncryptor
from keyexchange import DiffieHellman
from auth import Authentification

class chatServer:

    def __init__(self, Host, Port):
        self.HOST = Host
        self.PORT = Port
        self.BUFSIZ = 1024
        self.ADDR = (self.HOST, self.PORT)

        self.SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SERVER.bind(self.ADDR)

        self.CLIENT = None
        self.CLIENT_ADDR = None

        self.dh = DiffieHellman()
        self.encryptor = None
        
        self.accept_incoming_connection()
     
    def accept_incoming_connection(self):
        boolKey = None
        try:
            self.SERVER.listen(1)
            self.CLIENT, self.CLIENT_ADDR = self.SERVER.accept()
            print("{} has connected.".format(self.CLIENT_ADDR))
            try:
                auth = Authentification()
                boolAuth = auth.executeServer(self.CLIENT, "/Users/leonhagemann/Desktop/private.server.key", "/Users/leonhagemann/Desktop/selfsigned.client.crt")
                if boolAuth:
                    try:
                        aesKey = self.dh.executeServer(self.CLIENT)
                        print("Key succesfully exchanged...")
                        self.encryptor = AesEncryptor(aesKey)
                        print("Message encryption started...")
                    except Exception:
                        print("Can´t exchange Aes Key!")
                        raise SystemExit
                else:
                    print("Signature isn´t valid!")
                    sys.exit()
            except Exception:
                raise SystemExit
        except Exception:
            print("Connection error!")
            raise SystemExit
        print("WELCOME TO CRYPTCHAT 3.0")
        print("------------------------------------------------------------------")
        self.chatApp()
            
            
    def chatApp(self):
            Thread(target=self.receiveMessage).start()
            Thread(target=self.sendMessage).start()

    def receiveMessage(self):
        while True:
            try:
                tmp = self.CLIENT.recv(self.BUFSIZ)
                print(tmp)
                msg = self.encryptor.decrypt(tmp).decode('utf-8')
                print("CLIENT: ", msg)
                if msg.lower() == 'quit':
                    self.SERVER.close()
                    print('Other Party quit CryptChat!')
                    sys.exit()
            except Exception:
                raise SystemExit

    def sendMessage(self):
        while True:
            try:
                #msg = input("SERVER: ")
                msg = getpass.getpass(prompt="")
                if msg.lower() == 'quit':
                    tmp = self.encryptor.encrypt(msg)
                    print(tmp)
                    self.CLIENT.send(tmp)
                    print("SERVER: ", msg)
                    self.SERVER.close()
                    print('You quit CryptChat!')
                    sys.exit()
                else:
                    tmp = self.encryptor.encrypt(msg)
                    print(tmp)
                    self.CLIENT.send(tmp)
                    print("SERVER: ", msg)
            except Exception:
                print('Connection error!')
                raise SystemExit

if __name__ == '__main__':
    server = chatServer("127.0.0.1", 1234)
