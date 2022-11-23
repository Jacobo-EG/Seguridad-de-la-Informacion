from inspect import signature
from Crypto.PublicKey import ECC 
from Crypto.Hash import SHA256 
from Crypto.Signature import DSS

# Ver https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html 
# Ver https://pycryptodome.readthedocs.io/en/latest/src/signature/dsa.html

def crear_ECCKey():
# Use 'NIST P-256' 
    return ECC.generate(curve="P-256")

def guardar_ECCKey_Privada(fichero, key, password): 
    clave_cifrada = key.export_key(passphrase=password, pcks=8, protecction="PBKDF2WithHMAC-SHA1AndAES128-CBC")
    file = open(fichero, "wb")
    file.write(clave_cifrada)
    file.close()

def cargar_ECCKey_Privada(fichero, password):
    key_cif = open(fichero, "rb").read()
    key_priv = ECC.import_key(key_cif, passphrase=password)

    return key_priv

def guardar_ECCKey_Publica(fichero, key):
    key_pub = key.publickey().export_key()
    file = open(fichero, "wb")
    file.write(key_pub)
    file.close()

def cargar_ECCKey_Publica(fichero): 
    key_cif = open(fichero, "rb").read()
    key_pub = ECC.import_key(key_cif)

    return key_pub

# def cifrarECC_OAEP(cadena, key):
# El cifrado con ECC (ECIES) aun no está implementado
# Por lo tanto, no se puede implementar este método aun en la versión 3.9.7 return cifrado
# def descifrarECC_OAEP(cifrado, key):
# El cifrado con ECC (ECIES) aun no está implementado
# Por lo tanto, no se puede implementar este método aun en la versión 3.9.7 return cadena

def firmarECC_PSS(texto, key_private): 
    hash = SHA256.new(texto.encode("utf-8"))
    print(hash.hexdigest())
    sigN = DSS.new(key_private, "fips-186-3")
    signature = sigN.sign(hash)
    return signature

def comprobarECC_PSS(texto, firma, key_public):
    hash = SHA256.new(texto)
    verifier = DSS.new(key_public, "fips-186-3")
    try:
        verifier.verify(hash, firma)
        return True
    except (ValueError, TypeError):
        return False