#Creado por Jacobo Elicha Garrucho

from Crypto.Hash import SHA256, HMAC
import json
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
import funciones_rsa
from datetime import datetime

#=========== Creando clave =================
print("=========== Creando clave =================")

KTTP = funciones_rsa.crear_RSAKey()

#=========== Guardando clave publica TTP =================
print("=========== Guardando clave publica TTP =================")

funciones_rsa.guardar_RSAKey_Publica("TTP.pub",KTTP)

#=========== Creando conexiones =================

print("Esperando a Alice...")
socket_Alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Alice.escuchar()

print("Esperando a Bob...")
socket_Bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_Bob.escuchar()

#====================================== 1 ======================================
print("====================================== PASO 1 ======================================")
#=========== Recibiendo primer paquete =================
print("=========== Recibiendo primer paquete =================")

json_primerPaqCod = socket_Alice.recibir()

#=========== Chopping primer paquete =================

json_primerPaq = json_primerPaqCod.decode("utf-8")
print("A->T (cifrado || firma): " + json_primerPaq)
msj_Cif_str, firma_A_str = json.loads(json_primerPaq)

    #=========== Pasando a bytes =================

msj_Cif = bytearray.fromhex(msj_Cif_str)
firma_A = bytearray.fromhex(firma_A_str)

#=========== Cargamos clave publica de A =================
print("=========== Cargamos clave publica de A =================")

KPubA = funciones_rsa.cargar_RSAKey_Publica("KPubA.pub")

#=========== Desciframos el mensaje =================
print("=========== Desciframos el mensaje =================")

msj = funciones_rsa.descifrarRSA_OAEP(msj_Cif,KTTP)
print("A->T (claro): " + msj)

#=========== Chopping el mensaje =================

nombre, KAT_str = json.loads(msj)

    #=========== Pasamos la clave a bytes =================

KAT = bytearray.fromhex(KAT_str)

#=========== Comprobamos la firma =================
print("=========== Comprobamos la firma =================")

res = funciones_rsa.comprobarRSA_PSS(KAT,firma_A,KPubA)

if res:
    print("Firma verificada")
else:
    print("ERROR. FIRMA NO CORRECTA")
    exit(0)

#print(nombre)
#print(KAT.hex())

#====================================== 2 ======================================
print("====================================== PASO 2 ======================================")
#=========== Recibiendo segundo paquete =================
print("=========== Recibiendo segundo paquete =================")

json_segPaqCod = socket_Bob.recibir()

#=========== Chopping segundo paquete =================

json_segPaq = json_segPaqCod.decode("utf-8")
print("B->T (cifrado || firma): "+json_segPaq)
msj_Cif_str, firma_B_str = json.loads(json_segPaq)

    #=========== Pasando a bytes =================

msj_Cif = bytearray.fromhex(msj_Cif_str)
firma_B = bytearray.fromhex(firma_B_str)

#=========== Cargamos clave publica de B =================
print("=========== Cargamos clave publica de B =================")

KPubB = funciones_rsa.cargar_RSAKey_Publica("KPubB.pub")

#=========== Desciframos el mensaje =================
print("=========== Desciframos mensaje =================")

msj = funciones_rsa.descifrarRSA_OAEP(msj_Cif,KTTP)
print("B->T (claro): " + msj)

#=========== Chopping el mensaje =================

nombre, KBT_str = json.loads(msj)

    #=========== Pasamos la clave a bytes =================

KBT = bytearray.fromhex(KBT_str)

#=========== Comprobamos la firma =================
print("=========== Comprobamos la firma =================")

res = funciones_rsa.comprobarRSA_PSS(KBT,firma_B,KPubB)

if res:
    print("Firma verificada")
else:
    print("ERROR. FIRMA NO CORRECTA")
    exit(0)

#print(nombre)
#print(KBT.hex())

#====================================== 3 ======================================
print("====================================== PASO 3 ======================================")
#=========== Recibiendo tercer paquete =================
print("=========== Recibiendo tercer paquete =================")

json_tercerPaqCod = socket_Alice.recibir()

#=========== Chopping tercer paquete =================

json_tercerPaq = json_tercerPaqCod.decode("utf-8")
print("A->T (Alice || Bob):" + json_tercerPaq)
nombre_A, nombre_B = json.loads(json_tercerPaq)

if nombre_A != "Alice" or nombre_B != "Bob":
    exit(0)

#====================================== 4 ======================================
print("====================================== PASO 4 ======================================")
#=========== Creando cuarto paquete =================
print("=========== Creando cuarto paquete =================")

ts = datetime.timestamp(datetime.now())
KAB = funciones_aes.crear_AESKey()

cuartoPaq = []
cuartoPaq.append(ts)
cuartoPaq.append(KAB.hex())

    #=========== Creando encriptado B =================

json_crtPaq_B = json.dumps(cuartoPaq)
print("T->B [T->A->B] (claro): " + json_crtPaq_B)
gcm_cif_B= funciones_aes.iniciarAES_GCM(KBT)
cuartoPaq_B = json_crtPaq_B.encode("utf-8")
cuartoPaq_B_Cif, mac_B, nonce_16_ini_B = funciones_aes.cifrarAES_GCM(gcm_cif_B,cuartoPaq_B)
print("T->B [T->A->B] (cifrado): " + cuartoPaq_B_Cif.hex())

parte_B = []
parte_B.append(cuartoPaq_B_Cif.hex())
parte_B.append(mac_B.hex())
parte_B.append(nonce_16_ini_B.hex())
envio_B = json.dumps(parte_B)               #Le vamos a enviar la informacion || el nonce necesario para B

    #=========== Uniendo cuarto paquete =================

cuartoPaq.append(envio_B)
json_CuartoPaq = json.dumps(cuartoPaq)
cuartoPaq_d = json_CuartoPaq.encode("utf-8")
print("T->A (claro) : " + cuartoPaq_d.hex())

#=========== Ciframos cuarto paquete completo =================

gcm_cif_A = funciones_aes.iniciarAES_GCM(KAT)
cuartoPaq_A, mac_A, nonce_16_ini_A= funciones_aes.cifrarAES_GCM(gcm_cif_A,cuartoPaq_d)
print("T->A (cifrado): " + cuartoPaq_A.hex())

#=========== Preparamos el cuarto paquete || nonce_A =================

envio = []
envio.append(cuartoPaq_A.hex())
envio.append(mac_A.hex())
envio.append(nonce_16_ini_A.hex())
json_env = json.dumps(envio)
envio = json_env.encode("utf-8")

#=========== Enviando cuarto paquete =================

socket_Alice.enviar(envio)

#====================================== FINAL DE TTP ======================================

#=========== Cerramos conexiones =================

print("Cerrando conexion con Alice ...")
socket_Alice.cerrar()

print("Cerrando conexion con Bob ...")
socket_Bob.cerrar()