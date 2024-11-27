from encryption_decryption import *
#from Blinding_and_Signatures import *
from blind_signature import BlindSignature
import pandas as pd
import numpy as np


class Commission:
    def __init__(self, voters_tax_numbers: list[str], candidates_names: list[str]):
        """
        Ініціалізація комісії. Включає генерацію ключів для зв'язку та підпису.
        """
        self.private_comm_key, self.public_comm_key = generate_rsa_keys()
        self.voters_data = pd.DataFrame({
            'tax_number': voters_tax_numbers,
            'is_registered': np.zeros(len(voters_tax_numbers))
        })
        self.voters_data = self.voters_data.set_index('tax_number')
        self.candidates_data = pd.DataFrame({
            'Name': candidates_names,
            'Votes_Count': np.zeros(len(candidates_names))
        })
        self.received_ballots = {}

    def check_ballots_identity(self, current_ballot):
        # Розбиваємо бюлетені на компоненти
        current_ballot_parts = current_ballot.split('|')

        # Перевірка чи зареєстрований цей виборець в списках
        if current_ballot_parts[1] not in self.voters_data.index.tolist():
            raise ValueError("Виборця з таким ID не існує")

        # Перевірка чи не голосував виборець раніше
        if self.voters_data.loc[current_ballot_parts[1], 'is_registered'] != 0:
            raise ValueError("Виборець за таким ID вже зареєстрований")

        # Перевірка коректності вибору кандидата
        voter_choice = int(current_ballot_parts[2])
        if voter_choice < 1 or voter_choice > len(self.candidates_data):
            raise ValueError("Неправильний вибір кандидата")

        # Перевірка формату бюлетеня
        if len(current_ballot_parts) != 3:
            raise ValueError("Бюлетень складений некоректно")

    def register_ballot(self, ballot_kit: list[list[dict]], blind_ballots: list[bytes], bs: BlindSignature) -> list[tuple[bytes, int]]:
        """
        Перевірка бюлетенів та створення сліпих підписів для голосування.

        :param bs: Потрібен для роботи з сліпими підписами.
        :param ballot_kit: Набір зашифрованих бюлетенів.
        :param blind_ballots: Список засліплених бюлетенів.
        :return: Список сліпих підписів.
        """
        blind_signatures = []
        curr_voter_id = 0

        # Перевірка ідентичності бюлетенів
        for ballot_box in ballot_kit:
            for ballot in ballot_box:
                # Розшифровуємо поточний бюлетень
                ballot_id = rsa_decrypt(ballot['ballot_id'], self.private_comm_key)
                voter_id = rsa_decrypt(ballot['voter_id'], self.private_comm_key)
                voter_choice = rsa_decrypt(ballot['voter_choice'], self.private_comm_key)
                current_ballot = f"{ballot_id}|{voter_id}|{voter_choice}"

                # Перевіряємо ідентичність
                self.check_ballots_identity(current_ballot)
                curr_voter_id = voter_id

        # Створення сліпих підписів
        for hidden_ballot, encrypted_aes_key in blind_ballots:
            # Розшифровуємо прихований бюлетень
            decrypted_hidden_ballot = hybrid_decrypt(hidden_ballot, encrypted_aes_key, self.private_comm_key)

            # Створюємо підпис
            signature = bs.sign_blinded_message(decrypted_hidden_ballot)
            blind_signatures.append(signature)

        # Якщо перевірку пройдено, то вважаємо що цей виброець проголосував
        self.voters_data.loc[curr_voter_id, 'is_registered'] += 1

        return blind_signatures


    def count_vote(self, encrypted_ballot: bytes, encrypted_signature: bytes, aes_key: bytes, bs: BlindSignature):
        """
        Обробка зашифрованого голосу та підрахунок голосу для відповідного кандидата.

        :param bs:
        :param encrypted_ballot: Зашифрований бюлетень.
        :param encrypted_signature: Зашифрований підпис бюлетеня.
        :param aes_key: Зашифрований aes ключ підпису бюлетеня.
        """
        # Розшифровуємо повідомлення
        ballot = rsa_decrypt(encrypted_ballot, self.private_comm_key)
        signature = hybrid_decrypt(encrypted_signature, aes_key, self.private_comm_key)

        # Перевірка підпису
        is_valid = bs.verify(ballot.encode('utf-8'), signature)

        if not is_valid:
            raise ValueError("Відісланий підпис не пройшов перевірку")

        # Аналіз бюлетеня
        data = ballot.split('|')

        # Отримання id бюлетеня і перевірка чи є такий виборець
        ballot_id = data[0]
        if ballot_id in self.received_ballots.keys():
            raise ValueError("Бюлетень з таким ID вже зарахований")
        else:
            self.received_ballots.update({f'{ballot_id}': ballot})

        # Отримання голосу виборця, перевірка чи є такий кандидат і зарахування голосу якщо є
        candidate_number = data[2]
        if candidate_number.isdigit():
            number = int(candidate_number)

            if 1 <= number <= len(self.candidates_data):
                self.candidates_data.loc[number - 1, 'Votes_Count'] += 1
            else:
                raise ValueError(f"Кандидата під номером {number} не існує")

    def get_results(self):
        """Передає результати голосування"""
        num_of_voted = len(self.received_ballots)
        return self.candidates_data, num_of_voted, self.received_ballots

