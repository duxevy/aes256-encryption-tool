import pytest
from src import AES256Encryptor


@pytest.fixture
def encryptor():
    """Фикстура, создающая экземпляр шифровальщика для тестов."""
    return AES256Encryptor()


def test_padding():
    """Тест функции добавления и удаления padding."""
    # Проверяем разные длины данных
    test_cases = [
        b"test",  # 4 байта
        b"hello world",  # 11 байт
        b"x" * 16,  # ровно один блок
        b"y" * 32,  # ровно два блока
        b"",  # пустая строка
    ]

    for data in test_cases:
        padded = AES256Encryptor._pad(data)
        assert len(padded) % AES256Encryptor.BLOCK_SIZE == 0
        assert len(padded) >= len(data)
        assert AES256Encryptor._unpad(padded) == data


def test_key_derivation():
    """Тест функции генерации ключа."""
    password = "test_password"
    salt = b"0" * AES256Encryptor.SALT_SIZE

    key = AES256Encryptor._derive_key(password, salt)
    assert len(key) == AES256Encryptor.KEY_SIZE
    key2 = AES256Encryptor._derive_key(password, salt)
    assert key == key2
    key3 = AES256Encryptor._derive_key("another_pass", salt)
    assert key != key3


def test_encryption_decryption(encryptor):
    """Тест полного цикла шифрования и расшифрования."""
    test_cases = [
        "Простой текст",
        "Text with numbers 12345",
        "Текст с спецсимволами !@#$%^&*()",
        "Многострочный\nтекст\nс переносами",
        "",  # пустая строка
        "🌟 Unicode символы 测试",  # Unicode
        "a" * 1000,  # длинный текст
    ]

    password = "test_master_password"

    for text in test_cases:
        encrypted = encryptor.encrypt(password, text)
        assert encrypted != text
        decrypted = encryptor.decrypt(password, encrypted)
        assert decrypted == text


def test_corrupted_data(encryptor):
    """Тест на повреждённые данные."""
    original = "Тестовое сообщение"
    password = "test_password"

    encrypted = encryptor.encrypt(password, original)
    corrupted = encrypted[:-10] + "x" * 10  # Портим конец строки
    with pytest.raises(Exception):
        encryptor.decrypt(password, corrupted)

    with pytest.raises(Exception):
        encryptor.decrypt(password, "не_base64_строка")
