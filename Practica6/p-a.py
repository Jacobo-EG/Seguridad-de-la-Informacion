#Creado por Jacobo Elicha Garrucho

from Crypto.Hash import SHA256, HMAC
import json
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
import funciones_rsa

#=========== Creando clave =================

KAT = funciones_aes.crear_AESKey()

#=========== Creando conexion =================

print("Creando conexion con TTP...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

#====================================== 1 ======================================
print("====================================== PASO 1 ======================================")
#=========== Creando mensaje =================
print("=========== Creando mensaje =================")

msg_TE = []
msg_TE.append("Alice")
msg_TE.append(KAT.hex())
json_ET = json.dumps(msg_TE)

print("A -> T (claro): " + json_ET)

#=========== Recuperando clave TTP =================
print("=========== Recuperando clave TTP =================")

KPubTTP = funciones_rsa.cargar_RSAKey_Publica("TTP.pub")

#=========== Cifrando mensaje =================
print("=========== Cifrando mensaje =================")

msgCif = funciones_rsa.cifrarRSA_OAEP(json_ET,KPubTTP)

print("A->T (cifrado): " + msgCif.hex())

#=========== Firmando clave =================
print("=========== Firmando clave =================")

KA = funciones_rsa.crear_RSAKey()
KAPriv = KA

firma = funciones_rsa.firmarRSA_PSS(KAT,KA)

#=========== Guardando clave publica A =================
print("=========== Guardando clave publica =================")

funciones_rsa.guardar_RSAKey_Publica("KPubA.pub",KA)

#=========== Creando primer paquete =================
print("=========== Creando primer paquete =================")

primPaq = []
primPaq.append(msgCif.hex())
primPaq.append(firma.hex())
primPaq_d = json.dumps(primPaq)

print("A->T (cifrado || firma): " + msgCif.hex() + " || " + firma.hex())


#=========== Enviando primer paquete =================

primPaq = primPaq_d.encode("utf-8")
socket.enviar(primPaq)

#====================================== 3 ======================================
print("====================================== PASO 3 ======================================")
#=========== Creando tercer paquete =================
print("=========== Creando tercer paquete =================")

tercerPaq = []
tercerPaq.append("Alice")
tercerPaq.append("Bob")

json_Noms = json.dumps(tercerPaq)

print("A->T : " + json_Noms)

#=========== Enviando tercer paquete =================

tercerPaq_d = json_Noms.encode("utf-8")
socket.enviar(tercerPaq_d)

#====================================== 4 ======================================
print("====================================== PASO 4 ======================================")
#=========== Recibiendo cuarto paquete =================
print("=========== Recibiendo cuarto paquete =================")

envio_enc = socket.recibir()

#=========== Chopping cuarto paquete =================

envio = envio_enc.decode("utf-8")
paq_Cif_str, mac_str, nonce_16_ini_str = json.loads(envio)

print("T->A (cifrado): " + paq_Cif_str)


paq_Cif = bytearray.fromhex(paq_Cif_str)
mac = bytearray.fromhex(mac_str)
nonce_16_ini = bytearray.fromhex(nonce_16_ini_str)

#=========== Descifrando cuarto paquete =================
print("=========== Descifrando cuarto paquete =================")

paq_enc = funciones_aes.descifrarAES_GCM(KAT,nonce_16_ini,paq_Cif,mac)

#=========== Chopping descifrado =================

paq = paq_enc.decode("utf-8")

print("T->A (ts, KAB_str, paqueteB): " + paq)

ts, KAB_str, paqB_str = json.loads(paq)

    #=========== Transformando tipos =================

KAB = bytearray.fromhex(KAB_str)

#====================================== 5 ======================================
print("====================================== PASO 5 ======================================")
#=========== Conectando con Bob =================

print("Creando conexion con Bob...")
socket_Bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5555)
socket_Bob.conectar()

#=========== Preparando quinto paquete =================
print("=========== Creando quinto paquete =================")

quinto_Paq = []
quinto_Paq.append(paqB_str)

#=========== Cifrando datos quinto paquete =================
print("=========== Cifrando datos =================")

datos_quinto_paq = []
datos_quinto_paq.append("Alice")
datos_quinto_paq.append(ts)
json_quinto_paq_str = json.dumps(datos_quinto_paq)
json_quinto_paq = json_quinto_paq_str.encode("utf-8")

gcm_cif = funciones_aes.iniciarAES_GCM(KAB)
quinto_Paq_Cif, mac, nonce_16_ini = funciones_aes.cifrarAES_GCM(gcm_cif,json_quinto_paq)

print("A->B (cifrado): "+quinto_Paq_Cif.hex())

#=========== Añadiendo datos quinto paquete =================

quinto_Paq.append(quinto_Paq_Cif.hex())
quinto_Paq.append(mac.hex())
quinto_Paq.append(nonce_16_ini.hex())

#=========== Enviando quinto paquete =================

json_quinto_paq = json.dumps(quinto_Paq)
envio = json_quinto_paq.encode("utf-8")
socket_Bob.enviar(envio)

#====================================== 6 ======================================
print("====================================== PASO 6 ======================================")
#=========== Recibimos sexto paquete =================
print("=========== Recibiemos sexto paquete =================")

sexto_envio_enc = socket_Bob.recibir()
sexto_envio = sexto_envio_enc.decode("utf-8")

#=========== Chopping sexto paquete =================

ts_cif_str, mac_Bob_str, nonce_16_ini_Bob_str = json.loads(sexto_envio)

    #=========== Transformando datos =================

mac_Bob = bytearray.fromhex(mac_Bob_str)
nonce_16_ini_Bob = bytearray.fromhex(nonce_16_ini_Bob_str)
ts_cif = bytearray.fromhex(ts_cif_str)

#=========== Descifrando ts sexto paquete =================
print("=========== Descifrando paquete =================")

ts_Bob_enc = funciones_aes.descifrarAES_GCM(KAB,nonce_16_ini_Bob,ts_cif,mac_Bob)

ts_Bob_str = ts_Bob_enc.decode("utf-8")
ts_Bob = float.fromhex(ts_Bob_str)

#=========== Comprobando ts sexto paquete =================
print("=========== Comprobando Ts =================")

if ts+1 == ts_Bob:
    print("Ts correcto")
else:
    print("ERROR. Ts INCORRECTO")
    socket_Bob.cerrar()
    exit(0)

#====================================== 7 ======================================
print("====================================== PASO 7 ======================================")
#=========== Creando contenido septimo paquete =================
print("=========== Creando septimo paquete =================")

dni = "78984478v"
print("A->B (claro[dni]): "+dni)
dni_enc = dni.encode("utf-8")

#=========== Ciframos contenido septimo paquete =================

gcm_cif = funciones_aes.iniciarAES_GCM(KAB)
dni_enc_cif, mac, nonce_16_ini = funciones_aes.cifrarAES_GCM(gcm_cif,dni_enc)
print("A->B (cifrado[dni]): "+dni_enc_cif.hex())
#=========== Creamos septimo paquete =================

septimo_paq = []
septimo_paq.append(dni_enc_cif.hex())
septimo_paq.append(mac.hex())
septimo_paq.append(nonce_16_ini.hex())
septimo_paq_dump = json.dumps(septimo_paq)

#=========== Enviamos septimo paquete =================

septimo_paq_dump_enc = septimo_paq_dump.encode("utf-8")
socket_Bob.enviar(septimo_paq_dump_enc)

#====================================== 8 ======================================
print("====================================== PASO 8 ======================================")
#=========== Recibimos octavo paquete =================
print("=========== Recibimos octavo paquete =================")

octavo_paq_dump_enc = socket_Bob.recibir()
octavo_paq_dump = octavo_paq_dump_enc.decode("utf-8")

#=========== Chopping octavo paquete =================

apellido_enc_cif_str, mac_Bob_str, nonce_16_ini_Bob_str = json.loads(octavo_paq_dump)
print("B->A (cifrado[apellido]): "+apellido_enc_cif_str)

    #=========== Transformando datos =================

mac_Bob = bytearray.fromhex(mac_Bob_str)
nonce_16_ini_Bob = bytearray.fromhex(nonce_16_ini_Bob_str)
apellido_enc_cif = bytearray.fromhex(apellido_enc_cif_str)

#=========== Descifrando apellido =================
print("=========== Descifrando apellido =================")

apellido_enc = funciones_aes.descifrarAES_GCM(KAB,nonce_16_ini_Bob,apellido_enc_cif,mac_Bob)
apellido = apellido_enc.decode("utf-8")
print("B->A (claro[apellido]): "+apellido)

print("Cerrando conexion con Bob ...")
socket_Bob.cerrar()