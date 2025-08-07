import base64
import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Константы
SALT_SIZE = 16
KEY_SIZE = 32  # 256 бит
ITERATIONS = 100_000
BLOCK_SIZE = AES.block_size


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Генерирует криптографический ключ из пароля и соли с использованием PBKDF2

    Функция применяет алгоритм PBKDF2 (Password-Based Key Derivation Function 2)
    для преобразования пароля и соли в бинарный ключ заданной длины.

    Аргументы:
        password (str): Пароль в виде строки
        salt (bytes): Бинарные данные соли для увеличения энтропии

    Возвращает:
        bytes: Произведённый криптографический ключ длиной KEY_SIZE байт

    Константы:
        Использует глобальные параметры: KEY_SIZE (длина ключа) и ITERATIONS
        (количество итераций хеширования)
    """
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)


def pad(data: bytes) -> bytes:
    """
    Добавляет заполнение (padding) к данным для достижения длины, кратной BLOCK_SIZE

    Функция вычисляет необходимую длину заполнения и добавляет её к исходным данным.
    Значение каждого байта заполнения равно длине самого заполнения.

    Аргументы:
        data (bytes): Входные данные, к которым нужно добавить заполнение

    Возвращает:
        bytes: Данные с добавленным заполнением, общая длина которых кратна BLOCK_SIZE

    Константы:
        Использует глобальную константу BLOCK_SIZE (размер блока в байтах)

    Пример:
        Если BLOCK_SIZE = 16 и длина data = 14, результат будет data + b'\x02\x02'
    """
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len]) * padding_len


def unpad(data: bytes) -> bytes:
    """Удаляет дополнение PKCS7 из расшифрованных данных.

    Функция удаляет байты дополнения, добавленные при шифровании по схеме PKCS7.

    Аргументы:
        data: Байтовая строка с PKCS7 дополнением.

    Возвращает:
        bytes: Байтовая строка с удаленным дополнением.
    """
    return data[: -data[-1]]


def encrypt(master_password: str, plaintext: str) -> str:
    """
    Шифрует текст с использованием AES в режиме CBC

    Выполняет следующие шаги:
    1. Генерирует случайную соль (salt) и вектор инициализации (IV)
    2. Получает ключ шифрования из мастер-пароля и соли
    3. Добавляет заполнение к открытому тексту
    4. Шифрует данные
    5. Возвращает зашифрованные данные в base64-кодировке

    Аргументы:
        master_password (str): Основной пароль для генерации ключа
        plaintext (str): Текст для шифрования

    Возвращает:
        str: Base64-кодированная строка, содержащая:
             [salt][iv][зашифрованный_текст]

    Константы:
        Использует глобальные параметры: SALT_SIZE (размер соли),
        BLOCK_SIZE (размер блока AES) и использует ранее определенные функции:
        derive_key(), pad()
    """
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(master_password, salt)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode()))
    return base64.b64encode(salt + iv + ciphertext).decode()


def decrypt(master_password: str, b64data: str) -> str:
    """
    Расшифровывает данные, зашифрованные функцией encrypt

    Выполняет следующие шаги:
    1. Декодирует base64-строку в бинарные данные
    2. Разделяет данные на соль (salt), вектор инициализации (IV) и зашифрованный текст
    3. Генерирует ключ из мастер-пароля и соли
    4. Расшифровывает данные
    5. Удаляет заполнение (padding)

    Аргументы:
        master_password (str): Основной пароль, использованный при шифровании
        b64data (str): Base64-кодированная строка, содержащая:
                      [salt][iv][зашифрованный_текст]

    Возвращает:
        str: Расшифрованный открытый текст

    Константы:
        Использует глобальные параметры: SALT_SIZE (размер соли),
        BLOCK_SIZE (размер блока AES) и использует ранее определенные функции:
        derive_key(), unpad()

    Структура данных:
        - salt: первые SALT_SIZE байт
        - iv: следующие BLOCK_SIZE байт после соли
        - ciphertext: оставшиеся байты
    """
    raw = base64.b64decode(b64data)
    salt, iv, ciphertext = raw[:SALT_SIZE], raw[SALT_SIZE : SALT_SIZE + BLOCK_SIZE], raw[SALT_SIZE + BLOCK_SIZE :]
    key = derive_key(master_password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext)).decode()


def main():
    mode = input("Выберите режим (e — encrypt, d — decrypt): ").strip().lower()
    master_key = getpass.getpass("Введите мастер-ключ: ").strip()

    if mode == "e":
        plaintext = input("Введите строку для шифрования: ").strip()
        encrypted = encrypt(master_key, plaintext)
        print(f"Зашифровано:\n{encrypted}")
    elif mode == "d":
        b64data = input("Введите строку для расшифровки: ").strip()
        try:
            decrypted = decrypt(master_key, b64data)
            print(f"Расшифровано:\n{decrypted}")
        except Exception as e:
            print("Ошибка при расшифровке:", str(e))
    else:
        print("Неверный режим.")


if __name__ == "__main__":
    main()
