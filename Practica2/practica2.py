from re import A
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad

#Ejercicio1 -------------

msg = "Hola amigos de la seguridad".encode("utf-8")
msg2 = "Hola amigas de la seguridad".encode("utf-8")

key = get_random_bytes(16)
IV = get_random_bytes(16)
BLOCK_SIZE_AES = 16

print(msg)
print(msg2)

cipher = AES.new(key, AES.MODE_CBC, IV)
ciphertext = cipher.encrypt(pad(msg,BLOCK_SIZE_AES))
ciphertext2 = cipher.encrypt(pad(msg2,BLOCK_SIZE_AES))

print(ciphertext)
print(ciphertext2)

#Podemos observar mucha diferencia simplemente cambiando un caracter debido al EFECTO AVALANCHA

decipher_aes = AES.new(key, AES.MODE_CBC, IV)

d_msg = unpad(decipher_aes.decrypt(ciphertext),BLOCK_SIZE_AES).decode("utf-8","ignore")
d_msg2 = unpad(decipher_aes.decrypt(ciphertext2),BLOCK_SIZE_AES).decode("utf-8","ignore")

print(d_msg)
print(d_msg2)

#Ejercicio2 -------------

    #a

print(msg)

cipherA = AES.new(key, AES.MODE_ECB)
ciphertextA = cipherA.encrypt(pad(msg,BLOCK_SIZE_AES))

print(ciphertextA)

decipher_aesA = AES.new(key, AES.MODE_ECB)
d_msgA = unpad(decipher_aesA.decrypt(ciphertextA),BLOCK_SIZE_AES).decode("utf-8","ignore")

print(d_msgA)

    #b

print(msg)

nonce = get_random_bytes(BLOCK_SIZE_AES//2)

cipherB = AES.new(key, AES.MODE_CTR,nonce = nonce)
ciphertextB = cipherB.encrypt(pad(msg,BLOCK_SIZE_AES))

print(ciphertextB)

decipher_aesB = AES.new(key,AES.MODE_CTR,nonce=nonce)
d_msgB = unpad(decipher_aesB.decrypt(ciphertextB),BLOCK_SIZE_AES).decode("utf-8","ignore")
print(d_msgB)

    #c

print(msg)

cipherC = AES.new(key, AES.MODE_OFB,IV)
ciphertextC = cipherC.encrypt(pad(msg,BLOCK_SIZE_AES))

print(ciphertextC)

decipher_aesC = AES.new(key,AES.MODE_OFB,IV)
d_msgC = unpad(decipher_aesC.decrypt(ciphertextC),BLOCK_SIZE_AES).decode("utf-8","ignore")
print(d_msgC)

    #d

print(msg)

cipherD = AES.new(key,AES.MODE_CFB,IV)
ciphertextD = cipherD.encrypt(pad(msg,BLOCK_SIZE_AES))

print(ciphertextD)

decipher_aesD = AES.new(key,AES.MODE_CFB,IV)
d_msgD = unpad(decipher_aesD.decrypt(ciphertextD),BLOCK_SIZE_AES).decode("utf-8","ignore")
print(d_msgD)

    #e

print(msg)

nonce = get_random_bytes(BLOCK_SIZE_AES)

cipherE = AES.new(key,AES.MODE_GCM,nonce=nonce,mac_len=16)
ciphertextE = cipherE.encrypt(pad(msg,BLOCK_SIZE_AES))

print(ciphertextE)

decipher_aesE = AES.new(key,AES.MODE_GCM,nonce=nonce,mac_len=16)
d_msgE = unpad(decipher_aesE.decrypt(ciphertextE),BLOCK_SIZE_AES).decode("utf-8","ignore")
print(d_msgE)