from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
from Crypto.Signature import pss 
from Crypto.Hash import SHA256


key_cifrada = open("clave_Priv_Bob", "rb").read()
key_Priv = RSA.import_key(key_cifrada, passphrase="password")

keyFile = open("clave_Pub_Alice", "rb").read() 
key_Pub_Alice = RSA.import_key(keyFile)

cifrado = open("TextoCif","rb").read()
print(cifrado)
engineRSADescifrado = PKCS1_OAEP.new(key_Priv)
texto = engineRSADescifrado.decrypt(cifrado).decode("utf-8")
print(texto)

h = SHA256.new(texto.encode("utf-8")) 
verifier = pss.new(key_Pub_Alice)
firma = open("FirmaCif","rb").read()
try:
    verifier.verify(h, firma)
    print("--- Firma Correcta ---")
except (ValueError, TypeError):
    print("Error")