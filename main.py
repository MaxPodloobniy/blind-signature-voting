from encryption_decryption import *
from voter import Voter
from commission import Commission
import pandas as pd
import matplotlib.pyplot as plt
import hashlib


# Функція парсингу
def parse_and_encrypt_ballot(ballot_text, commission_public_key):
    # Парсимо дані
    ballot_id_line = next(line for line in ballot_text.split("\n") if line.startswith("Ідентифікатор бюлетеня:"))
    ballot_id = ballot_id_line.split(": ")[1].strip()

    voter_id_line = next(line for line in ballot_text.split("\n") if line.startswith("Ідентифікатор виборця:"))
    voter_id = voter_id_line.split(": ")[1].strip()

    choice_line = next(line for line in ballot_text.split("\n") if line.startswith("Ваш вибір:"))
    voter_choice = choice_line.split(": ")[1].strip()

    # Окреме шифрування кожного значення
    encrypted_ballot_id = rsa_encrypt(ballot_id, commission_public_key)

    encrypted_voter_id = rsa_encrypt(voter_id, commission_public_key)

    encrypted_voter_choice = rsa_encrypt(voter_choice, commission_public_key)

    # Повертаємо словник з зашифрованими значеннями
    return {
        'ballot_id': encrypted_ballot_id,
        'voter_id': encrypted_voter_id,
        'voter_choice': encrypted_voter_choice
    }


def main():
    # Завантаження даних виборців і кандидатів
    tax_numbers = pd.read_excel('data/voters_numbers.xlsx', dtype=int)
    tax_numbers = tax_numbers['Voter_ID'].tolist()
    candidates_names = pd.read_excel('data/candidates.xlsx')
    candidates_names = candidates_names['Candidates'].tolist()

    # Створення списку прихованих ID виборців
    hidden_tax_numbers = []

    for voter_tax_num in tax_numbers:
        hidden_tax_num = hashlib.sha1(str(voter_tax_num).encode('utf-8')).hexdigest()
        hidden_tax_numbers.append(hidden_tax_num)

    # Ініціалізація комісії
    commission = Commission(hidden_tax_numbers, candidates_names)

    print("Систему запущено")
    print(f"Знайдено {len(hidden_tax_numbers)} виборців")
    print(f"Знайдено {len(candidates_names)} кандидатів")

    while True:
        # ----------------------- Авторизація виборця -----------------------
        print('\nЗареєструйтесь, для цього введіть свій номер виборця')
        print(f'Всього зареєстровано {len(hidden_tax_numbers)} виборців')

        voters_num = input("Введіть номер виборця ")

        # Перевірка валідності введеного номера
        if str(voters_num).isdigit():
            voters_num = int(voters_num)
        else:
            raise ValueError("Ви неправильно ввели свій номер за списком")

        if not (1 <= voters_num <= len(hidden_tax_numbers)):
            raise ValueError(f"Номер виборця має бути від 1 до {len(hidden_tax_numbers)}")

        print('\nАвторизація успішна!\n')

        # ----------------------- Реєстрація бюлетенів виборця -----------------------
        print("Генеруємо і реєструємо бюлетені")
        # Створюємо об'єкт виборця
        current_voter = Voter(hidden_tax_numbers[voters_num - 1], candidates_names)

        # Шифруємо набір бюлетенів
        encrypted_ballot_kit = []
        for ballot_box in current_voter.ballot_kit:
            encrypted_box = []
            for ballot_text in ballot_box:
                # Парсинг і шифрування бюлетеня
                encrypted_ballot = parse_and_encrypt_ballot(ballot_text, commission.public_comm_key)
                encrypted_box.append(encrypted_ballot)
            encrypted_ballot_kit.append(encrypted_box)

        # Шифруємо сліпі бюлетені
        encrypted_blind_ballots = []
        for blind_ballot in current_voter.blind_ballots:
            encrypted_blind_ballots.append(hybrid_encrypt(blind_ballot, commission.public_comm_key))

        # Реєстрація бюлетенів і отримання сліпих підписів
        blind_signatures = commission.register_ballot(encrypted_ballot_kit, encrypted_blind_ballots, current_voter.bs)

        print('Бюлетені зареєстровано!\n')

        # ----------------------- Вибір кандидата виборцем -----------------------
        print('Список кандидатів:')
        for name in candidates_names:
            print(name)

        voters_choice = input("Введіть номер кандидата за якого будете голосувати ")

        # Перевірка валідності вибору кандидата
        if str(voters_choice).isdigit():
            voters_choice = int(voters_choice)
        else:
            raise ValueError("Ви неправильно ввели номер кандидата")

        if not (1 <= voters_choice <= len(candidates_names)):
            raise ValueError(f"Номер кандидата має бути від 1 до {len(candidates_names)}")


        # ----------------------- Обробка голосу виборця -----------------------
        # Шифруємо обраний бюлетень і його підпис
        encrypted_voting_ballot = rsa_encrypt(
            current_voter.ballot_texts[voters_choice-1],
            commission.public_comm_key
        )

        # Розсліплюємо підпис
        unblinded_sig = current_voter.bs.unblind_signature(
            blind_signatures[voters_choice-1],
            current_voter.generated_r[voters_choice-1]
        )

        # Шифруємо підпис для передачі комісії
        encrypted_voting_signature, sign_aes_key = hybrid_encrypt(
            unblinded_sig,
            commission.public_comm_key)

        # Підрахунок голосу
        commission.count_vote(encrypted_voting_ballot, encrypted_voting_signature, sign_aes_key, current_voter.bs)

        print(f"\nГолос виборця {voters_num} за кандидата {candidates_names[voters_choice - 1]} успішно зараховано")

        # ----------------------- Результати голосування -----------------------

        code = input("Введіть 1 якщо хочете продовжити, 2 якщо завершити голосування ")

        if str(code).isdigit():
            code = int(code)
        else:
            raise ValueError("Ви неправильно ввели код")

        if code == 1:
            continue
        elif code == 2:
            candidates_results, number_of_voted, counted_ballots = commission.get_results()

            # Візуалізуємо результати голосувань
            plt.figure(figsize=(10, 6))
            plt.bar(candidates_results['Name'], candidates_results['Votes_Count'])
            plt.title('Голоси кандидатів')
            plt.xlabel('Кандидати')
            plt.ylabel('Кількість голосів')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.show()

            index_of_winner = candidates_results['Votes_Count'].idxmax()
            print(f"Найбільше голосів у {candidates_results.loc[index_of_winner, 'Name']}")
            print(f"Явка склала {number_of_voted} чол. або {number_of_voted/len(tax_numbers) * 100}%")

            print("\nЗараховані бюлетені\n")
            for ballot_id, ballot in counted_ballots.items():
                print(f"ID бюлетеня: {ballot_id}; Текст: {ballot}")

            exit()
        else:
            ValueError("Код повинен бути 1 або 2")


if __name__ == '__main__':
    main()