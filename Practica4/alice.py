import json
import funciones_aes
import funciones_rsa
from socket_class import SOCKET_SIMPLE_TCP
from Crypto.Hash import HMAC, SHA256

#--------------------------------------------------------- Crea conexion -----------------------------

socketclient = SOCKET_SIMPLE_TCP('127.0.0.1',5551)
socketclient.conectar()

#--------------------------------------------------------- Crea y carga claves -----------------------------

k1 = funciones_aes.crear_AESKey()
k2 = funciones_aes.crear_AESKey()

key_pub_B = funciones_rsa.cargar_RSAKey_Publica("rsa_bob.pub")
key_priv_A = funciones_rsa.cargar_RSAKey_Privada("rsa_alice.pem","alice")

#--------------------------------------------------------- Cifra claves y firma -----------------------------

k1_cif = funciones_rsa.cifrarRSA_OAEP_BIN(k1,key_pub_B)
k2_cif = funciones_rsa.cifrarRSA_OAEP_BIN(k2,key_pub_B)

firma = funciones_rsa.firmarRSA_PSS(k1+k2,key_priv_A)

print("Carga claves")

#--------------------------------------------------------- Primer Envio -----------------------------

socketclient.enviar(k1_cif)
socketclient.enviar(k2_cif)     #Convertir en un solo envio
socketclient.enviar(firma)

print("Envia claves k1 y k2")

#--------------------------------------------------------- Segundo envio -----------------------------

aes_ctr_cifrado, nonce_16_iniA = funciones_aes.iniciarAES_CTR_cifrado(k1)

socketclient.enviar(funciones_rsa.cifrarRSA_OAEP_BIN(nonce_16_iniA, key_pub_B))

nonce_16_iniB = funciones_rsa.descifrarRSA_OAEP_BIN(socketclient.recibir(), key_priv_A) 

aes_ctr_descifrado = funciones_aes.iniciarAES_CTR_descifrado(k1,nonce_16_iniB)


mensaje = []
mensaje.append("Alice")
nonce = funciones_aes.get_random_bytes(128)
mensaje.append(nonce.hex())
jStr = json.dumps(mensaje)

hmac = HMAC.new(k2,digestmod=SHA256)
hmac.update(jStr.encode("utf-8"))

jStrEnc = jStr.encode("utf-8")

aliceYNonceCifrado = funciones_aes.cifrarAES_CTR(aes_ctr_cifrado, jStrEnc)

print(type(aliceYNonceCifrado))
print(aliceYNonceCifrado)

segundoPaq = []
segundoPaq.append(aliceYNonceCifrado.hex())
segundoPaq.append(hmac.hexdigest())
jStr2Paq = json.dumps(segundoPaq)

socketclient.enviar(jStr2Paq.encode("utf-8"))
print("Envia segundo paquete")

#--------------------------------------------------------- Recibre respuesta ---------------------------

tercerPaqCifEnc = socketclient.recibir()

print("Recibe respuesta")

#--------------------------------------------------------- Cierra conexion -----------------------------

socketclient.cerrar()