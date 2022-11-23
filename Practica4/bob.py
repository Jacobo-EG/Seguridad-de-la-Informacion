import json
import funciones_aes
import funciones_rsa
from socket_class import SOCKET_SIMPLE_TCP
from Crypto.Hash import HMAC, SHA256
import codecs

socketserver = SOCKET_SIMPLE_TCP('127.0.0.1',5551)
socketserver.escuchar()

#--------------------------------------------------------- Carga claves -----------------------------

key_pub_A = funciones_rsa.cargar_RSAKey_Publica("rsa_alice.pub")
key_priv_B = funciones_rsa.cargar_RSAKey_Privada("rsa_bob.pem","bob")

print("Carga claves")

#--------------------------------------------------------- Recibe claves -----------------------------

k1_cif = socketserver.recibir()         
k2_cif = socketserver.recibir()         #tendria que ser solo un envio desde alice 
firma = socketserver.recibir()

k1 = funciones_rsa.descifrarRSA_OAEP_BIN(k1_cif,key_priv_B)
k2 = funciones_rsa.descifrarRSA_OAEP_BIN(k2_cif,key_priv_B)

print("Recibe claves k1 y k2")

#--------------------------------------------------------- Comprueba firma -----------------------------

if funciones_rsa.comprobarRSA_PSS(k1+k2,firma,key_pub_A):
    print("Firma verificada")
else:
    print("Error en la firma")
    exit()

#--------------------------------------------------------- Inicio Cifrados y Descifrados y Comparto Vectores Inciales ------------------

nonce_16_iniACif = socketserver.recibir()
nonce_16_iniA = funciones_rsa.descifrarRSA_OAEP_BIN(nonce_16_iniACif, key_priv_B)

aes_ctr_cifrado, nonce_16_iniB = funciones_aes.iniciarAES_CTR_cifrado(k1)
socketserver.enviar(funciones_rsa.cifrarRSA_OAEP_BIN(nonce_16_iniB,key_pub_A))

aes_ctr_descifrado = funciones_aes.iniciarAES_CTR_descifrado(k1,nonce_16_iniA)

#--------------------------------------------------------- Recibo Segundo Paquete ------------------

segPaqEnc = socketserver.recibir()
print(segPaqEnc)
segPaq = json.loads(segPaqEnc.decode("utf-8"))
print(segPaq)
aliceYNonceCifStr, hmac = segPaq
aliceYNonceCif = bytearray.fromhex(aliceYNonceCifStr)

aliceYNonceEnc = funciones_aes.descifrarAES_CTR(aes_ctr_descifrado, aliceYNonceCif)
aliceYNoncejStr = aliceYNonceEnc.decode("utf-8")
aliceYNonce = json.loads(aliceYNoncejStr)
alice, nonce = aliceYNonce

print("Recibe mensaje")

#--------------------------------------------------------- Comprueba mensaje -----------------------------


h = HMAC.new(k2, digestmod=SHA256)
h.update(aliceYNoncejStr.encode("utf-8"))
try:
   h.hexverify(hmac)
   print("The message is authentic")
except ValueError:
    print("The message or the key is wrong")
    exit()

#--------------------------------------------------------- Crea y envia respuesta -----------------------------

mensaje = []
mensaje.append(alice)
mensaje.append("Bob")
mensaje.append(nonce)
jStr = json.dumps(mensaje)
mensajeCif = funciones_aes.cifrarAES_CTR(aes_ctr_cifrado,jStr.encode("utf-8"))

hmac = HMAC.new(k2,digestmod=SHA256)
hmac.update(k2)

paquete = []
paquete.append(mensajeCif.hex())
paquete.append(hmac.hexdigest())
jStrPaq = json.dumps(paquete)

socketserver.enviar(jStrPaq.encode("utf-8"))
