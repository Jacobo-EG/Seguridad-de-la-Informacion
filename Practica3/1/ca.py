from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
from Crypto.Signature import pss 
from Crypto.Hash import SHA256

#--------- Alice -------------

key_A = RSA.generate(2048)
key_pub_A = key_A.public_key()

key_cifrada = key_A.export_key(passphrase="password", pkcs=8, protection="scryptAndAES128-CBC") 
file_out = open("clave_Priv_Alice", "wb")
file_out.write(key_cifrada)
file_out.close()

key_pub_cif = key_pub_A.export_key() 
file_out = open("clave_Pub_Alice", "wb") 
file_out.write(key_pub_cif) 
file_out.close()

#---------- Bob -----------

key_B = RSA.generate(2048)
key_pub_B = key_B.public_key()

key_cifrada = key_B.export_key(passphrase="password", pkcs=8, protection="scryptAndAES128-CBC") 
file_out = open("clave_Priv_Bob", "wb")
file_out.write(key_cifrada)
file_out.close()

key_pub_cif = key_pub_B.export_key() 
file_out = open("clave_Pub_Bob", "wb") 
file_out.write(key_pub_cif) 
file_out.close()