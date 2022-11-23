# 1 -------------------

def cifradoCesarAlfabetoInglesMAY(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + 3) % 26) + 65
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

claroCESAR = 'VENI VIDI VINCI ZETA'
print(claroCESAR)
cifradoCESAR = cifradoCesarAlfabetoInglesMAY(claroCESAR) 
print(cifradoCESAR)

def descifradoCesarAlfabetoInglesMAY(cadena):
    """Devuelve un texto en calro (mensaje) de un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenCifrado = ord(cadena[i])
        ordenDescifrado = 0
        # Cambia el caracter a cifrar
        if (ordenCifrado >= 65 and ordenCifrado <= 90):
            ordenDescifrado = (((ordenCifrado - 65) - 3) % 26) + 65
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenDescifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

claroCESAR = 'VENI VIDI VINCI ZETA'
print(claroCESAR)
descifradoCESAR = descifradoCesarAlfabetoInglesMAY(cifradoCESAR) 
print(descifradoCESAR)

# 2 -------------------

def cifradoCesarAlfabetoInglesMAYMIN(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + 3) % 26) + 65
        elif (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) + 3) % 26) + 97
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

claroCESAR = 'VENI vidi VINCI zeta'
print(claroCESAR)
cifradoCESAR = cifradoCesarAlfabetoInglesMAYMIN(claroCESAR) 
print(cifradoCESAR)

def descifradoCesarAlfabetoInglesMAYMIN(cadena):
    """Devuelve un texto en calro (mensaje) de un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenCifrado = ord(cadena[i])
        ordenDescifrado = 0
        # Cambia el caracter a cifrar
        if (ordenCifrado >= 65 and ordenCifrado <= 90):
            ordenDescifrado = (((ordenCifrado - 65) - 3) % 26) + 65
        elif (ordenCifrado >= 97 and ordenCifrado <= 122):
            ordenDescifrado = (((ordenCifrado - 97) - 3) % 26) + 97 
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenDescifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

claroCESAR = 'VENI vidi VINCI zeta'
print(claroCESAR)
descifradoCESAR = descifradoCesarAlfabetoInglesMAYMIN(cifradoCESAR) 
print(descifradoCESAR)

# 3 -------------

def cifradoCesarAlfabetoInglesMAYMINGen(cadena,k):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + 3) % (k*26)) + 65
        elif (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) + 3) % (k*26)) + 97
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

claroCESAR = 'VENI vidi VINCI zeta'
print(claroCESAR)
cifradoCESAR = cifradoCesarAlfabetoInglesMAYMINGen(claroCESAR,2) 
print(cifradoCESAR)

def descifradoCesarAlfabetoInglesMAYMINGen(cadena,k):
    """Devuelve un texto en calro (mensaje) de un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenCifrado = ord(cadena[i])
        ordenDescifrado = 0
        # Cambia el caracter a cifrar
        if (ordenCifrado >= 65 and ordenCifrado <= 90):
            ordenDescifrado = (((ordenCifrado - 65) - 3) % (k*26)) + 65
        elif (ordenCifrado >= 97 and ordenCifrado <= 122):
            ordenDescifrado = (((ordenCifrado - 97) - 3) % (k*26)) + 97 
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenDescifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

claroCESAR = 'VENI vidi VINCI zeta'
print(claroCESAR)
descifradoCESAR = descifradoCesarAlfabetoInglesMAYMINGen(cifradoCESAR,2) 
print(descifradoCESAR)
