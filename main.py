from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Generar un par de claves RSA
def generar_claves():
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

# Cifrar un mensaje usando la clave pública
def cifrar_mensaje(mensaje, clave_publica):
    mensaje_cifrado = clave_publica.encrypt(
        mensaje.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensaje_cifrado

# Descifrar un mensaje usando la clave privada
def descifrar_mensaje(mensaje_cifrado, clave_privada):
    mensaje_descifrado = clave_privada.decrypt(
        mensaje_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensaje_descifrado.decode()

# Guardar claves en archivos
def guardar_claves(clave_privada, clave_publica):
    with open("keys/clave_privada.pem", "wb") as f:
        f.write(clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("keys/clave_publica.pem", "wb") as f:
        f.write(clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Cargar claves desde archivos
def cargar_claves():
    with open("keys/clave_privada.pem", "rb") as f:
        clave_privada = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    with open("keys/clave_publica.pem", "rb") as f:
        clave_publica = serialization.load_pem_public_key(f.read())
    return clave_privada, clave_publica

# Programa principal
if __name__ == "__main__":
    # Generar claves
    clave_privada, clave_publica = generar_claves()

    # Guardar claves en archivos
    guardar_claves(clave_privada, clave_publica)

    # Cargar claves desde archivos
    clave_privada, clave_publica = cargar_claves()

    # Mensaje a cifrar
    mensaje = "Este es un mensaje seguro."
    print("Mensaje original:", mensaje)

    # Cifrar el mensaje
    mensaje_cifrado = cifrar_mensaje(mensaje, clave_publica)
    print("\nMensaje cifrado:", mensaje_cifrado)

    # Descifrar el mensaje
    mensaje_descifrado = descifrar_mensaje(mensaje_cifrado, clave_privada)
    print("\nMensaje descifrado:", mensaje_descifrado)
