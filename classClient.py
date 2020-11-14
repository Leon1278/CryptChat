import socket, getpass, sys
from threading import Thread
from encryptor import AesEncryptor
from keyexchange import DiffieHellman
from auth import Authentification

class chatClient():

    def __init__(self, Host, Port):
        self.HOST = Host
        self.PORT = Port
        self.BUFSIZ = 1024
        self.ADDR = (self.HOST, self.PORT)

        self.CLIENT_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.dh = DiffieHellman()
        self.encryptor = None
        
        self.connect()
        
    def connect(self):
        try:
            self.CLIENT_SOCKET.connect(self.ADDR)
            try:
                auth = Authentification()
                bool = auth.executeClient(self.CLIENT_SOCKET, "/Users/leonhagemann/Desktop/private.client.key", "/Users/leonhagemann/Desktop/selfsigned.server.crt")
                if bool:
                    try:
                        aesKey = self.dh.executeClient(self.CLIENT_SOCKET)
                        print("Key succesfully exchanged...")
                        self.encryptor = AesEncryptor(aesKey)
                        print("Message encryption started...")
                    except:
                        print("Can´t exchange Aes Key!")
                        raise SystemExit
                else:
                    print("Signature isn't valid!")
                    sys.exit()
            except Exception:
                raise SystemExit
        except Exception:
            print("Can´t connect to server...")
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
                tmp = self.CLIENT_SOCKET.recv(self.BUFSIZ)
                print(tmp)
                msg = self.encryptor.decrypt(tmp).decode('utf-8')
                print("SERVER: ", msg)
                if msg.lower() == 'quit':
                    self.CLIENT_SOCKET.close()
                    print('Other Party quit CryptChat!')
                    sys.exit()
            except Exception:
                print('Connection error!')
                raise SystemExit

    def sendMessage(self):
        while True:
            try:
                #msg = input("CLIENT: ")
                msg = getpass.getpass(prompt="")
                if msg.lower() == 'quit':
                    tmp = self.encryptor.encrypt(msg)
                    print(tmp)
                    self.CLIENT_SOCKET.send(tmp)
                    print("CLIENT: ", msg)
                    self.CLIENT_SOCKET.close()
                    print('You quit CryptChat!')
                    sys.exit()
                else:
                    tmp = self.encryptor.encrypt(msg)
                    print(tmp)
                    self.CLIENT_SOCKET.send(tmp)
                    print("CLIENT: ", msg)
            except Exception:
                print('Connection error!')
                raise SystemExit

if __name__ == '__main__':
    client = chatClient("127.0.0.1", 1234)
