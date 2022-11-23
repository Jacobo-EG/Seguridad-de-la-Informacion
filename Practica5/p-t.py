from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes

# Paso 0: Crea las claves que T comparte con B y A
##################################################

# Crear Clave KAT, guardar a fichero
KAT = funciones_aes.crear_AESKey()
FAT = open("KAT.bin", "wb")
FAT.write(KAT)
FAT.close()

# Crear Clave KBT, guardar a fichero
KBT = funciones_aes.crear_AESKey()
FBT = open("KBT.bin", "wb")
FBT.write(KBT)
FBT.close()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de escucha de Bob (5551)
print("Esperando a Bob...")
socket_Bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Bob.escuchar()

# Crea la respuesta para B y A: K1 y K2
K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()

# Recibe el mensaje
primerRec = socket_Bob.recibir()
primerRecDec = primerRec.decode("utf-8")
cifradoHex, cifrafo_macHex, cifrado_nonceHex = json.loads(primerRecDec)

cifrado = bytearray.fromhex(cifradoHex)
cifrado_mac = bytearray.fromhex(cifrafo_macHex)
cifrado_nonce = bytearray.fromhex(cifrado_nonceHex)

"""
cifrado = socket_Bob.recibir()
cifrado_mac = socket_Bob.recibir()
cifrado_nonce = socket_Bob.recibir()
"""

# Descifro los datos con AES GCM
datos_descifrado_ET = funciones_aes.descifrarAES_GCM(KBT, cifrado_nonce, cifrado, cifrado_mac)

# Decodifica el contenido: Bob, Nb
json_ET = datos_descifrado_ET.decode("utf-8" ,"ignore")
print("B -> T (descifrado): " + json_ET)
msg_ET = json.loads(json_ET)

# Extraigo el contenido
t_bob, t_nb = msg_ET
t_nb = bytearray.fromhex(t_nb)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################
msg_B = []
msg_B.append(K1.hex())
msg_B.append(K2.hex())
msg_B.append(t_nb.hex())
json_B = json.dumps(msg_B)
print("T -> B (descifrado): " + json_B)

aes_engine_B = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine_B,json_B.encode("utf-8"))

paqB = []
paqB.append(cifrado.hex())
paqB.append(cifrado_mac.hex())
paqB.append(cifrado_nonce.hex())
json_B = json.dumps(paqB)

socket_Bob.enviar(json_B.encode("utf-8"))

print("K1: ")
print(K1)
print("K2: ")
print(K2)

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket_Bob.cerrar() 

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

print("Esperando a Alice...")
socket_Alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_Alice.escuchar()

segRec = socket_Alice.recibir()
segRecDec = segRec.decode("utf-8")
cifradoHex, cifrafo_macHex, cifrado_nonceHex = json.loads(segRecDec)

cifrado = bytearray.fromhex(cifradoHex)
cifrado_mac = bytearray.fromhex(cifrafo_macHex)
cifrado_nonce = bytearray.fromhex(cifrado_nonceHex)

datos_descifrado_ET = funciones_aes.descifrarAES_GCM(KAT, cifrado_nonce, cifrado, cifrado_mac)

json_ET = datos_descifrado_ET.decode("utf-8" ,"ignore")
print("A -> T (descifrado): " + json_ET)
msg_ET = json.loads(json_ET)

t_alice, t_na = msg_ET
t_na = bytearray.fromhex(t_na)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################

msg_A = []
msg_A.append(K1.hex())
msg_A.append(K2.hex())
msg_A.append(t_na.hex())
json_A = json.dumps(msg_A)
print("T -> A (descifrado): " + json_A)

aes_engine_A = funciones_aes.iniciarAES_GCM(KAT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine_A,json_A.encode("utf-8"))

paqA = []
paqA.append(cifrado.hex())
paqA.append(cifrado_mac.hex())
paqA.append(cifrado_nonce.hex())
json_A = json.dumps(paqA)

socket_Alice.enviar(json_A.encode("utf-8"))