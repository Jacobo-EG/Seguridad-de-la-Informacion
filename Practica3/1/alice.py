from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
from Crypto.Signature import pss 
from Crypto.Hash import SHA256

key_cifrada = open("clave_Priv_Alice", "rb").read()
key_Priv = RSA.import_key(key_cifrada, passphrase="password")

keyFile = open("clave_Pub_Bob", "rb").read() 
key_Pub_Bob = RSA.import_key(keyFile)

texto = "Hola amigos de la seguridad".encode("utf-8")
engineRSACifrado = PKCS1_OAEP.new(key_Pub_Bob)
cifrado = engineRSACifrado.encrypt(texto)
print(cifrado)

file_Cif = open("TextoCif","wb")
file_Cif.write(cifrado)
file_Cif.close()


h = SHA256.new(texto)
signature = pss.new(key_Priv).sign(h)

file_Cif = open("FirmaCif","wb")
file_Cif.write(signature)
file_Cif.close()