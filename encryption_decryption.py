import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding as symmetric_padding


# Генерація пари ключів RSA
def generate_rsa_keys(key_size=1024):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(message, public_key):
    """
    Шифрує повідомлення за допомогою публічного ключа RSA з компактними налаштуваннями.

    :param message: Повідомлення у вигляді строки.
    :param public_key: Об'єкт публічного ключа RSA.
    :return: Зашифроване повідомлення у вигляді байтів.
    """
    # Якщо повідомлення це рядок
    if isinstance(message, str):
        message = message.encode('utf-8')

    try:
        encrypted_message = public_key.encrypt(
            message,
            asymmetric_padding.PKCS1v15()  # Компактніший padding
        )
        return encrypted_message
    except Exception as e:
        print(f"Помилка шифрування: {e}")
        raise

def rsa_decrypt(encrypted_message, private_key):
    """
    Розшифровує повідомлення за допомогою приватного ключа RSA з компактними налаштуваннями.

    :param encrypted_message: Зашифроване повідомлення у вигляді байтів.
    :param private_key: Об'єкт приватного ключа RSA.
    :return: Розшифроване повідомлення у вигляді рядка.
    """
    try:
        decrypted_message = private_key.decrypt(
            encrypted_message,
            asymmetric_padding.PKCS1v15()  # Відповідний padding для розшифрування
        )
        return decrypted_message.decode('utf-8')
    except Exception as e:
        print(f"Помилка дешифрування: {e}")
        raise


# Гібридне дешифрування підпису
def hybrid_decrypt(encrypted_signature, encrypted_aes_key, private_key):
    # Розшифрування AES-ключа
    decrypted_key_iv = private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.PKCS1v15()
    )

    aes_key = decrypted_key_iv[:32]
    iv = decrypted_key_iv[32:]

    # Розшифрування підпису
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_signature = decryptor.update(encrypted_signature) + decryptor.finalize()

    unpadder = symmetric_padding.PKCS7(algorithms.AES.block_size).unpadder()
    signature = unpadder.update(padded_signature) + unpadder.finalize()

    return signature


# Гібридне шифрування підпису
def hybrid_encrypt(signature, public_key):
    # Перевірка типу та конвертація, якщо потрібно
    if not isinstance(signature, bytes):
        signature = str(signature).encode('utf-8')

    aes_key = os.urandom(32)  # 256-бітний ключ
    iv = os.urandom(16)  # Initialization Vector

    # Шифрування підпису AES
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_signature = padder.update(signature) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_signature = encryptor.update(padded_signature) + encryptor.finalize()

    # Шифрування AES-ключа RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key + iv,  # Передаємо і ключ, і IV
        asymmetric_padding.PKCS1v15()
    )

    return encrypted_signature, encrypted_aes_key