import getpass
from src import AES256Encryptor


def main():
    """Основная функция для работы класса."""
    encryptor = AES256Encryptor()
    mode = input("Выберите режим (e — encrypt, d — decrypt): ").strip().lower()
    master_key = getpass.getpass("Введите мастер-ключ: ").strip()

    if mode == "e":
        plaintext = input("Введите строку для шифрования: ").strip()
        encrypted = encryptor.encrypt(master_key, plaintext)
        print(f"Зашифровано:\n{encrypted}")
    elif mode == "d":
        b64data = input("Введите строку для расшифровки: ").strip()
        try:
            decrypted = encryptor.decrypt(master_key, b64data)
            print(f"Расшифровано:\n{decrypted}")
        except Exception as e:
            print("Ошибка при расшифровке:", str(e))
    else:
        print("Неверный режим.")


if __name__ == "__main__":
    main()
