

from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KBT
KBT = open("KBT.bin", "rb").read()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de conexion con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Bob")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("B -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
primerPaq = []
primerPaq.append(cifrado.hex())
primerPaq.append(cifrado_mac.hex())
primerPaq.append(cifrado_nonce.hex())
primerPaqjStr = json.dumps(primerPaq)
primerPaqEnv = primerPaqjStr.encode("utf-8")

socket.enviar(primerPaqEnv)

"""
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)
"""

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################
json_ClavesEnc = socket.recibir()
json_Claves = json_ClavesEnc.decode("utf-8")
cifradoHex, cifrado_macHex, cifrado_nonceHex = json.loads(json_Claves)

cifrado = bytearray.fromhex(cifradoHex)
cifrado_mac = bytearray.fromhex(cifrado_macHex)
cifrado_nonce = bytearray.fromhex(cifrado_nonceHex)
paqClaves = funciones_aes.descifrarAES_GCM(KBT,cifrado_nonce,cifrado,cifrado_mac)
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

# Cerramos el socket entre B y T, no lo utilizaremos mas

socket.cerrar() 

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

print("Esperando a Alice...")
socket_Alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socket_Alice.escuchar()

json_N_Enc = socket_Alice.recibir()

json_N = json_N_Enc.decode("utf-8")
nameCifHex, nonce_16_iniHex, hmac_N = json.loads(json_N)

nameCif = bytearray.fromhex(nameCifHex)
nonce_16_ini_A = bytearray.fromhex(nonce_16_iniHex)

ctr_descif_A = funciones_aes.iniciarAES_CTR_descifrado(K1,nonce_16_ini_A)
nameEnc = funciones_aes.descifrarAES_CTR(ctr_descif_A,nameCif)
name = nameEnc.decode("utf-8")

hmac = HMAC.new(K2,digestmod=SHA256)
hmac.update(name.encode("utf-8"))

try:
    hmac.hexverify(hmac_N)
    print("Mensaje correcto")
except ValueError:
    print("Mensaje ALTERADO.")
    print("ABORTANDO COMUNICACION...")
    socket.cerrar()
    exit()


print("Nombre: " + name)

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

apellido = "Elicha"
ctr_cif_B, nonce_16_ini_B = funciones_aes.iniciarAES_CTR_cifrado(K1)
apellidoCif = funciones_aes.cifrarAES_CTR(ctr_cif_B, apellido.encode("utf-8"))

hmac = HMAC.new(K2,digestmod=SHA256)
hmac.update(apellido.encode("utf-8"))

paq2 = []
paq2.append(apellidoCif.hex())
paq2.append(nonce_16_ini_B.hex())
paq2.append(hmac.hexdigest())

jStr2 = json.dumps(paq2)

socket_Alice.enviar(jStr2.encode("utf-8"))

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

json_End_Enc = socket_Alice.recibir()

json_End = json_End_Enc.decode("utf-8")
EndCifHex, hmac_End = json.loads(json_End)

EndCif = bytearray.fromhex(EndCifHex)

EndEnc = funciones_aes.descifrarAES_CTR(ctr_descif_A, EndCif)
End = EndEnc.decode("utf-8")

hmac = HMAC.new(K2,digestmod=SHA256)
hmac.update(End.encode("utf-8"))

try:
    hmac.hexverify(hmac_End)
    print("Mensaje correcto")
except ValueError:
    print("Mensaje ALTERADO.")
    print("ABORTANDO COMUNICACION...")
    socket.cerrar()
    exit()


print(End)

socket_Alice.cerrar()