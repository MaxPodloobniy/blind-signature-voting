from Crypto.PublicKey import RSA
import random

class BlindSignature:
    def __init__(self, key_size=2048):
        # Генерація RSA ключів
        self.key = RSA.generate(key_size)
        self.public_key = self.key.publickey()

    def blind_message(self, message):
        """Засліплення повідомлення"""
        # Якщо повідомлення рядок, то переводимо в байти
        if isinstance(message, str):
            message = message.encode('utf-8')

        n = self.public_key.n
        e = self.public_key.e

        # Генерація фактора засліплення
        while True:
            r = random.randint(2, n - 1)
            if pow(r, 1, n) != 0:
                break

        # Перетворення повідомлення в число
        m = int.from_bytes(message, 'big')

        # Засліплення
        blinded_m = (m * pow(r, e, n)) % n
        blinded_bytes = blinded_m.to_bytes((blinded_m.bit_length() + 7) // 8, 'big')

        return blinded_bytes, r

    def sign_blinded_message(self, blinded_message):
        """Підписання засліпленого повідомлення"""
        blinded_int = int.from_bytes(blinded_message, 'big')
        signed = pow(blinded_int, self.key.d, self.key.n)
        return signed.to_bytes((signed.bit_length() + 7) // 8, 'big')

    def unblind_signature(self, signed_blinded, r):
        """Розсліплення підпису"""
        n = self.key.n
        signed_int = int.from_bytes(signed_blinded, 'big')

        # Знаходження оберненого елементу
        r_inv = pow(r, -1, n)

        unblinded = (signed_int * r_inv) % n
        return unblinded.to_bytes((unblinded.bit_length() + 7) // 8, 'big')

    def verify(self, message: bytes, signature: bytes):
        """Перевірка підпису"""
        m = int.from_bytes(message, 'big')
        sig = int.from_bytes(signature, 'big')

        # Пряма перевірка
        verified = pow(sig, self.public_key.e, self.public_key.n) == m
        return verified