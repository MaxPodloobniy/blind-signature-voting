"""
Клас Voter моделює виборця у системі голосування. Виборець може генерувати бюлетені,
засліплювати їх для підпису комісією, а також вибирати та шифрувати бюлетень для відправки.
"""

from encryption_decryption import *
from blind_signature import BlindSignature
from crypto_tools import *
import hashlib


class Voter:
    def __init__(self, hashed_tax_number, candidates_list):
        # Генеруємо ключі RSA
        self.private_key_object, self.public_key_object = generate_rsa_keys()
        # Ховаємо ІПН за хешем
        self.hidden_tax_number = hashed_tax_number
        # Створюємо об'єкт класу з імлпементацією сліпого підпису
        self.bs = BlindSignature()
        # Створюємо
        self.candidates = candidates_list
        # Створення декількох наборів бюлетенів для перевірки комісією
        self.ballot_kit = self.generate_all_unsafe_ballots()
        # Створення сліпих бюлетенів
        self.blind_ballots, self.generated_r, self.ballot_texts = self.generate_safe_ballots()

    def generate_all_unsafe_ballots(self, num_of_ballots=4):
        """Генерує всі не сліпі бюлетені для перевірки комісією"""
        all_unsafe_ballots = []

        for i in range(num_of_ballots):
            ballot_box = []

            for q in range(len(self.candidates)):
                ballot = generate_ballot_text(q + 1, self.hidden_tax_number, self.candidates)
                ballot_box.append(ballot)

            all_unsafe_ballots.append(ballot_box)

        return all_unsafe_ballots


    def generate_safe_ballots(self):
        """
        Генерація засліплених бюлетенів із текстами бюлетенів і засліплювальними множниками.
        """
        blind_ballots = []  # Засліплені хеші
        unblinding_factors = []  # Засліплювальні множники r
        ballots_texts = []  # Тексти всіх бюлетенів

        for i in range(len(self.candidates)):
            # Унікальний ID бюлетеня
            timestamp = datetime.now().isoformat().encode('utf-8')
            ballot_id = hashlib.sha1(timestamp).hexdigest()
            ballot_id = ballot_id[:10]  # Беремо перші 10 символів

            # Формуємо текст бюлетеня
            ballot_text = f"{ballot_id}|None|{i+1}"
            ballots_texts.append(ballot_text)

            # Засліплюємо бюлетень
            blinded_ballot, r = self.bs.blind_message(ballot_text)

            # Додаємо засліплений бюлетень і засліплювальний множник
            blind_ballots.append(blinded_ballot)
            unblinding_factors.append(r)

        return blind_ballots, unblinding_factors, ballots_texts


