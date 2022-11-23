#Creado por Jacobo Elicha Garrucho

from Crypto.Hash import SHA256, HMAC
import json
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
import funciones_rsa

#=========== Creando clave =================

KBT = funciones_aes.crear_AESKey()

#=========== Creando conexion =================

print("Creando conexion con TTP...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket.conectar()

#====================================== 2 ======================================
print("====================================== PASO 2 ======================================")
#=========== Creando mensaje =================
print("=========== Creando mensaje =================")

msg_TE = []
msg_TE.append("Bob")
msg_TE.append(KBT.hex())
json_ET = json.dumps(msg_TE)

print("B -> T (descifrado): " + json_ET)

#=========== Recuperando clave TTP =================
print("=========== Recuperando clave TTP =================")

KPubTTP = funciones_rsa.cargar_RSAKey_Publica("TTP.pub")

#=========== Cifrando mensaje =================
print("=========== Cifrando mensaje =================")

msgCif = funciones_rsa.cifrarRSA_OAEP(json_ET,KPubTTP)

print("B->T (cifrado): " + msgCif.hex())

#=========== Firmando clave =================
print("=========== Firmando =================")

KB = funciones_rsa.crear_RSAKey()
KBPriv = KB

firma = funciones_rsa.firmarRSA_PSS(KBT,KB)

#=========== Guardando clave publica B =================
print("=========== Guardando clave publica B =================")

funciones_rsa.guardar_RSAKey_Publica("KPubB.pub",KB)

#=========== Creando segundo paquete =================
print("=========== Creando segundo paquete =================")

segPaq = []
segPaq.append(msgCif.hex())
segPaq.append(firma.hex())
segPaq_d = json.dumps(segPaq)

print("B->T (cifrado || firma): " + segPaq_d)

#=========== Enviando segundo paquete =================
print("=========== Enviando segundo paquete =================")

segPaq = segPaq_d.encode("utf-8")
socket.enviar(segPaq)

#====================================== 5 ======================================
print("====================================== PASO 5 ======================================")
#=========== Conectando con Alice =================

print("Esperando a Alice...")
socket_Alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5555)
socket_Alice.escuchar()

#=========== Recibiendo quinto paquete =================
print("=========== Recibiendo quinto paquete =================")

quinto_paq_enc = socket_Alice.recibir()

#=========== Chopping quinto paquete =================

quinto_paq = quinto_paq_enc.decode("utf-8")
datos_TTP, datos_Alice_str, mac_Alice_str, nonce_16_ini_Alice_str = json.loads(quinto_paq)

print("T->A->B (cifrado): " + datos_TTP)
print("A->B (cifrado): "+ datos_Alice_str)

    #=========== Pasando tipos quinto paquete =================

datos_Alice_cif = bytearray.fromhex(datos_Alice_str)
mac_Alice = bytearray.fromhex(mac_Alice_str)
nonce_16_ini_Alice = bytearray.fromhex(nonce_16_ini_Alice_str)

#=========== Chopping datos TTP quinto paquete =================

datos_TTP_cif_str, mac_TTP_str, nonce_16_ini_TTP_str = json.loads(datos_TTP)

    #=========== Transformando datos TTP quinto paquete =================

datos_TTP_cif = bytearray.fromhex(datos_TTP_cif_str)
mac_TTP = bytearray.fromhex(mac_TTP_str)
nonce_16_ini_TTP = bytearray.fromhex(nonce_16_ini_TTP_str)

#=========== Desciframos datos TTP =================
print("=========== Descifrando datos TTP =================")

datos_TTP_enc = funciones_aes.descifrarAES_GCM(KBT,nonce_16_ini_TTP,datos_TTP_cif,mac_TTP)
datos_TTP = datos_TTP_enc.decode("utf-8")
print("T->A->B (claro): " + datos_TTP)

ts_TTP, KAB_str = json.loads(datos_TTP)
KAB = bytearray.fromhex(KAB_str)

#=========== Desciframos datos Alice quinto paquete =================
print("=========== Desciframos datos Alice =================")

datos_Alice_enc = funciones_aes.descifrarAES_GCM(KAB,nonce_16_ini_Alice,datos_Alice_cif,mac_Alice)
datos_Alice = datos_Alice_enc.decode("utf-8")
print("A->B (claro): " + datos_Alice)

nombre, ts_Alice = json.loads(datos_Alice)

#=========== Comprobamos que los campos de alice sean correctos =================
print("=========== Comprobamos los datos =================")

if nombre == "Alice":
    print("Nombre correcto")
else:
    print("ERROR. NOMBRE INCORRECTO.")
    socket_Alice.cerrar()
    exit(0)

if ts_Alice == ts_TTP:
    print("Ts correcto")
else:
    print("ERROR. TIMESTAMP INCORRECTO.")
    socket_Alice.cerrar()
    exit(0)

#====================================== 6 ======================================
print("====================================== PASO 6 ======================================")
#=========== Respondemos a Alice con Ts+1 =================
print("=========== Respondemos a Alice con Ts+1 =================")

ts = ts_Alice+1

#=========== Ciframos Ts+1 =================
print("=========== Ciframos Ts+1 =================")

ts_str = ts.hex()
ts_enc = ts_str.encode("utf-8")

cifrado_gcm = funciones_aes.iniciarAES_GCM(KAB)
ts_cif, mac_Bob, nonce_16_ini_Bob = funciones_aes.cifrarAES_GCM(cifrado_gcm,ts_enc)

print("B->A (cifrado): " + ts_cif.hex())

#=========== Creamos sexto paquete =================

sexto_paq = []
sexto_paq.append(ts_cif.hex())
sexto_paq.append(mac_Bob.hex())
sexto_paq.append(nonce_16_ini_Bob.hex())
sexto_envio = json.dumps(sexto_paq)

#=========== Enviamos sexto paquete =================

sexto_envio_enc = sexto_envio.encode("utf-8")
socket_Alice.enviar(sexto_envio_enc)


#====================================== 7 ======================================
print("====================================== PASO 7 ======================================")
#=========== Recibimos septimo paquete =================
print("=========== Recibimos septimo paquete =================")

septimo_paq_dump_enc = socket_Alice.recibir()
septimo_paq_dump = septimo_paq_dump_enc.decode("utf-8")

#=========== Chopping septimo paquete =================

dni_enc_cif_str, mac_Alice_str, nonce_16_ini_Alice_str = json.loads(septimo_paq_dump)
print("A->B (cifrado[dni]): " + dni_enc_cif_str)

    #=========== Transformando datos =================

mac_Alice = bytearray.fromhex(mac_Alice_str)
nonce_16_ini_Alice = bytearray.fromhex(nonce_16_ini_Alice_str)
dni_enc_cif = bytearray.fromhex(dni_enc_cif_str)

#=========== Descifrando dni =================
print("=========== Descifrando dni =================")

dni_enc = funciones_aes.descifrarAES_GCM(KAB,nonce_16_ini_Alice,dni_enc_cif,mac_Alice)
dni = dni_enc.decode("utf-8")
print("A->B (claro[dni]): " + dni)

#====================================== 8 ======================================
print("====================================== PASO 8 ======================================")
#=========== Creando contenido octavo paquete =================
print("=========== Creando octavo paquete =================")

apellido = "Elicha"
print("B->A (claro[apellido]): "+apellido)
apellido_enc = apellido.encode("utf-8")

#=========== Ciframos contenido octavo paquete =================
print("=========== Ciframos octavo paquete =================")

gcm_cif = funciones_aes.iniciarAES_GCM(KAB)
apellido_enc_cif, mac, nonce_16_ini = funciones_aes.cifrarAES_GCM(gcm_cif,apellido_enc)
print("B->A (cifrado[apellido]): "+apellido_enc_cif.hex())

#=========== Creamos octavo paquete =================

octavo_paq = []
octavo_paq.append(apellido_enc_cif.hex())
octavo_paq.append(mac.hex())
octavo_paq.append(nonce_16_ini.hex())
octavo_paq_dump = json.dumps(octavo_paq)

#=========== Enviamos octavo paquete =================

octavo_paq_dump_enc = octavo_paq_dump.encode("utf-8")
socket_Alice.enviar(octavo_paq_dump_enc)

#====================================== Cerramos conexion ======================================

print("Cerrando conexion con Alice ...")
socket_Alice.cerrar()