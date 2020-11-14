import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

class Authentification:
    
    def load_certification(self, certFilePath):
        pem_cert = open(certFilePath, 'rb').read()
        cert = x509.load_pem_x509_certificate(pem_cert, backend=default_backend())
        return cert

    def load_private_key(self, keyFilePath):
        pem_key = open(keyFilePath, 'rb').read()
        key = serialization.load_pem_private_key(pem_key, password=None, backend=default_backend())
        return key

    def signChallenge(self, bytes, key):
        signature = key.sign(bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature

    def signatureValid(self, cert, signature, bytes):
        pub_key = cert.public_key()
        try:
            pub_key.verify(signature, bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            print('valid!')
            return True
        except Exception as e:
            print('invalid!', e)
            return False
            
    def executeClient(self, socket, authKeyFile, partnerAuthCertFile):
        print("Client Authentification started!")
        cert = self.load_certification(partnerAuthCertFile)
        privKey = self.load_private_key(authKeyFile)
        challenge = get_random_bytes(8)
        socket.send(challenge)
        print("sending challenge to server...")
        sig_response = socket.recv(1024)
        print("received server side signed challenge...")
        other_challenge = socket.recv(1024)
        print("received servers challenge")
        sig = self.signChallenge(other_challenge, privKey)
        socket.send(sig)
        print("client side signed challenge sent...")
        bool = self.signatureValid(cert, sig_response, challenge)
        return bool
        

    def executeServer(self, socket, authKeyFile, partnerAuthCertFile):
        print("Server Authentification started!")
        cert = self.load_certification(partnerAuthCertFile)
        privKey = self.load_private_key(authKeyFile)
        other_challenge = socket.recv(1024)
        print("received clients challenge...")
        sig = self.signChallenge(other_challenge, privKey)
        socket.send(sig)
        print("server side signed challenge sent...")
        challenge = get_random_bytes(8)
        socket.send(challenge)
        print("sending challenge to client...")
        sig_response = socket.recv(1024)
        print("received client side signed challenge...")
        bool = self.signatureValid(cert, sig_response, challenge)
        return bool




