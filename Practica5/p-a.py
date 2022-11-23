
from os import name
from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################
KAT = open("KAT.bin", "rb").read()

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket.conectar()

t_n_origen = get_random_bytes(16)

msg_TE = []
msg_TE.append("Alice")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("A -> T (descifrado): " + json_ET)

aes_engine = funciones_aes.iniciarAES_GCM(KAT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

primerPaq = []
primerPaq.append(cifrado.hex())
primerPaq.append(cifrado_mac.hex())
primerPaq.append(cifrado_nonce.hex())
primerPaqjStr = json.dumps(primerPaq)
primerPaqEnv = primerPaqjStr.encode("utf-8")

socket.enviar(primerPaqEnv)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################

json_ClavesEnc = socket.recibir()
json_Claves = json_ClavesEnc.decode("utf-8")
cifradoHex, cifrado_macHex, cifrado_nonceHex = json.loads(json_Claves)

cifrado = bytearray.fromhex(cifradoHex)
cifrado_mac = bytearray.fromhex(cifrado_macHex)
cifrado_nonce = bytearray.fromhex(cifrado_nonceHex)
paqClaves = funciones_aes.descifrarAES_GCM(KAT,cifrado_nonce,cifrado,cifrado_mac)
K1Hex, K2Hex, t_nHex = json.loads(paqClaves)

K1 = bytearray.fromhex(K1Hex)
K2 = bytearray.fromhex(K2Hex)
t_n = bytearray.fromhex(t_nHex)

print("K1: ")
print(K1)
print("K2: ")
print(K2)

if t_n != t_n_origen:
    print("Error en el t_n")
    exit()

socket.cerrar()

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

print("Creando conexion con B...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socket.conectar()

name = "Jacobo"
ctr_cif_A, nonce_16_ini_A = funciones_aes.iniciarAES_CTR_cifrado(K1)
nameCif = funciones_aes.cifrarAES_CTR(ctr_cif_A, name.encode("utf-8"))

hmac = HMAC.new(K2,digestmod=SHA256)
hmac.update(name.encode("utf-8"))

paq1 = []
paq1.append(nameCif.hex())
paq1.append(nonce_16_ini_A.hex())
paq1.append(hmac.hexdigest())

jStr1 = json.dumps(paq1)

socket.enviar(jStr1.encode("utf-8"))

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

json_Ap_Enc = socket.recibir()

json_Ap = json_Ap_Enc.decode("utf-8")
apellidoCifHex, nonce_16_iniHex, hmac_Ap = json.loads(json_Ap)

apellidoCif = bytearray.fromhex(apellidoCifHex)
nonce_16_ini_B = bytearray.fromhex(nonce_16_iniHex)

ctr_descif_B = funciones_aes.iniciarAES_CTR_descifrado(K1,nonce_16_ini_B)
apellidoEnc = funciones_aes.descifrarAES_CTR(ctr_descif_B, apellidoCif)
apellido = apellidoEnc.decode("utf-8")

hmac = HMAC.new(K2,digestmod=SHA256)
hmac.update(apellido.encode("utf-8"))

try:
    hmac.hexverify(hmac_Ap)
    print("Mensaje correcto")
except ValueError:
    print("Mensaje ALTERADO.")
    print("ABORTANDO COMUNICACION...")
    socket.cerrar()
    exit()


print("Apellido: " + apellido)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################
end = "END"
endCif = funciones_aes.cifrarAES_CTR(ctr_cif_A, end.encode("utf-8"))

hmac = HMAC.new(K2,digestmod=SHA256)
hmac.update(end.encode("utf-8"))

paq1 = []
paq1.append(endCif.hex())
paq1.append(hmac.hexdigest())

jStr1 = json.dumps(paq1)

socket.enviar(jStr1.encode("utf-8"))

socket.cerrar()