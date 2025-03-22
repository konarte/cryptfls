import os
import sys
import lzma
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def xor_encrypt_decrypt(data, key):
    """
    Простое шифрование/дешифрование XOR для строки.

    :param data: Строка для шифрования/дешифрования.
    :param key: Ключ XOR.
    :return: Преобразованная строка.
    """
    key_bytes = key[:len(data)]  # Используем часть ключа, равную длине данных
    return bytes([b ^ k for b, k in zip(data, key_bytes)])

def generate_unique_filename(directory, base_name, extension):
    """
    Генерирует уникальное имя файла, добавляя номер перед расширением.

    :param directory: Директория, где находится файл.
    :param base_name: Базовое имя файла.
    :param extension: Расширение файла.
    :return: Уникальное имя файла.
    """
    counter = 1
    while True:
        unique_name = f"{base_name}.{counter}{extension}"
        if not os.path.exists(os.path.join(directory, unique_name)):
            return unique_name
        counter += 1

def generate_key(directory, key_save_directory=None):
    """
    Генерирует случайный ключ шифрования AES (128 бит) и сохраняет его в файл вместе с путем.

    :param directory: Директория для шифрования.
    :param key_save_directory: Директория для сохранения ключа (опционально).
    :return: Путь к файлу ключа и номер ключа.
    """
    base_name = "encryption_key"
    extension = ".key"
    key_directory = key_save_directory if key_save_directory else directory
    key_file_name = generate_unique_filename(key_directory, base_name, extension)
    key = os.urandom(16)  # 16 байт = 128 бит

    # Шифруем путь XOR
    encrypted_path = xor_encrypt_decrypt(directory.encode(), key)

    with open(os.path.join(key_directory, key_file_name), 'wb') as key_file:
        key_file.write(key)  # Записываем ключ
        key_file.write(encrypted_path)  # Записываем зашифрованный путь

    key_number = int(key_file_name.split('.')[1])  # Извлекаем номер из имени файла
    print(f"Ключ шифрования сохранен в файл: {os.path.join(key_directory, key_file_name)}")
    return key_file_name, key_number

def list_keys(directory):
    """
    Находит все файлы ключей в директории и возвращает их список.

    :param directory: Директория для поиска ключей.
    :return: Список файлов ключей.
    """
    keys = [file for file in os.listdir(directory) if file.endswith('.key')]
    return keys

def load_key(directory, key_file):
    """
    Загружает ключ шифрования и путь из указанного файла.

    :param directory: Директория, где находится ключ.
    :param key_file: Имя файла ключа.
    :return: Ключ шифрования и путь.
    """
    key_file_path = os.path.join(directory, key_file)
    if not os.path.exists(key_file_path):
        raise FileNotFoundError(f"Ключ шифрования '{key_file}' не найден.")

    with open(key_file_path, 'rb') as key_file:
        key = key_file.read(16)  # Первые 16 байт - это ключ
        encrypted_path = key_file.read()  # Остальная часть - зашифрованный путь

    # Расшифровываем путь XOR
    decrypted_path = xor_encrypt_decrypt(encrypted_path, key).decode()
    return key, decrypted_path

def compress_data(data, compression_level):
    """
    Сжимает данные с использованием LZMA.

    :param data: Данные для сжатия.
    :param compression_level: Уровень сжатия (0-9).
    :return: Сжатые данные.
    """
    return lzma.compress(data, preset=compression_level)

def decompress_data(data):
    """
    Распаковывает данные с использованием LZMA.

    :param data: Сжатые данные.
    :return: Распакованные данные.
    """
    return lzma.decompress(data)

def encrypt_file(file_path, key, key_number, compression_level=0):
    """
    Шифрует файл с использованием AES и, при необходимости, сжимает его.

    :param file_path: Путь к файлу, который нужно зашифровать.
    :param key: Ключ шифрования.
    :param key_number: Номер ключа.
    :param compression_level: Уровень сжатия (0-9).
    :return: Путь к зашифрованному файлу.
    """
    iv = os.urandom(16)  # Генерация случайного IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    if compression_level > 0:
        plaintext = compress_data(plaintext, compression_level)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file_path = f"{file_path}.{key_number}.enc"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + ciphertext)

    return encrypted_file_path

def decrypt_file(file_path, key):
    """
    Расшифровывает файл с использованием AES и, при необходимости, распаковывает его.

    :param file_path: Путь к файлу, который нужно расшифровать.
    :param key: Ключ шифрования.
    :return: Путь к расшифрованному файлу.
    """
    try:
        with open(file_path, 'rb') as encrypted_file:
            data = encrypted_file.read()
            if len(data) < 16:
                raise ValueError("Файл слишком мал для расшифровки (отсутствует IV или данные повреждены).")

            iv = data[:16]  # Первые 16 байт - это IV
            ciphertext = data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        try:
            # Попытка распаковать данные
            plaintext = decompress_data(plaintext)
        except lzma.LZMAError:
            pass  # Если данные не сжаты, просто пропускаем распаковку

        # Генерация уникального имени для расшифрованного файла
        base_name, extension = os.path.splitext('.'.join(file_path.split('.')[:-2]))  # Убираем .<key_number>.enc
        counter = 1
        while True:
            if counter == 1:
                decrypted_file_path = f"{base_name}{extension}"
            else:
                decrypted_file_path = f"{base_name}.{counter}{extension}"
            if not os.path.exists(decrypted_file_path):
                break
            counter += 1

        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)

        return decrypted_file_path
    except Exception as e:
        print(f"Ошибка при расшифровке файла '{file_path}': {e}")
        return None

def process_directory(directory, key, key_number, decrypt=False, compression_level=0, delete_original=False):
    """
    Рекурсивно обрабатывает все файлы в директории.

    :param directory: Директория для обработки.
    :param key: Ключ шифрования/расшифровки.
    :param key_number: Номер ключа.
    :param decrypt: Если True, выполняется расшифровка. По умолчанию - шифрование.
    :param compression_level: Уровень сжатия (0-9).
    :param delete_original: Если True, оригинальные файлы удаляются после шифрования.
    """
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)

            # Игнорируем файлы ключа и уже зашифрованные файлы
            if filename.endswith('.key') or (decrypt and not filename.endswith(f'.{key_number}.enc')):
                continue

            try:
                if decrypt:
                    decrypted_file_path = decrypt_file(file_path, key)
                    if decrypted_file_path:
                        print(f"Файл '{file_path}' расшифрован. Расшифрованный файл: {decrypted_file_path}")
                else:
                    # Шифруем только файлы, которые не являются зашифрованными
                    if not filename.endswith('.enc'):
                        encrypted_file_path = encrypt_file(file_path, key, key_number, compression_level)
                        print(f"Файл '{file_path}' зашифрован. Зашифрованный файл: {encrypted_file_path}")

                        if delete_original:
                            os.remove(file_path)
                            print(f"Оригинальный файл '{file_path}' удален.")
            except Exception as e:
                print(f"Ошибка при обработке файла '{file_path}': {e}")

def select_key(directory):
    """
    Позволяет пользователю выбрать ключ из списка.

    :param directory: Директория для поиска ключей.
    """
    keys = list_keys(directory)
    if not keys:
        print("Ошибка: В указанной директории нет файлов ключей (.key).")
        return

    print("Доступные ключи:")
    for i, key_file in enumerate(keys, start=1):
        try:
            key, decrypted_path = load_key(directory, key_file)
            print(f"{i}. {key_file} - Путь: {decrypted_path}")
        except Exception as e:
            print(f"{i}. {key_file} - Ошибка загрузки пути: {e}")

    key_choice = input("Выберите номер ключа (или 0 для выхода): ").strip()
    if key_choice == '0':
        return

    if not key_choice.isdigit() or int(key_choice) < 1 or int(key_choice) > len(keys):
        print("Неверный выбор ключа.")
        return

    key_file = keys[int(key_choice) - 1]
    try:
        key, decrypted_path = load_key(directory, key_file)
        key_number = int(key_file.split('.')[1])  # Извлекаем номер ключа из имени файла
        print(f"Загружен ключ шифрования: {key_file}")
        print(f"Путь обработки: {decrypted_path}")

        action = input("Хотите дешифровать файлы? (1 - да, 0 - выйти): ").strip()
        if action == '1':
            process_directory(decrypted_path, key, key_number, decrypt=True)
    except Exception as e:
        print(f"Ошибка при работе с ключом: {e}")

def main():
    print("=== Меню ===")
    print("1. Шифрование")
    print("2. Дешифрование")
    mode = input("Выберите режим (1 или 2): ").strip()
    if mode not in ['1', '2']:
        print("Неверный выбор режима.")
        return

    target_directory = input("Введите путь к директории для обработки: ").strip()
    if not os.path.isdir(target_directory):
        print(f"Ошибка: Директория '{target_directory}' не существует.")
        return

    if mode == '1':
        key_save_directory_input = input("Директория для сохранения ключа (по умолчанию текущая): ").strip()
        key_save_directory = key_save_directory_input if key_save_directory_input else target_directory

        if not os.path.isdir(key_save_directory):
            print(f"Ошибка: Директория '{key_save_directory}' не существует.")
            return

        key_file_name, key_number = generate_key(target_directory, key_save_directory)
        key = load_key(key_save_directory, key_file_name)[0]

        compression_level_input = input("Введите уровень сжатия (0-9, по умолчанию 0): ").strip()
        compression_level = int(compression_level_input) if compression_level_input.isdigit() and 0 <= int(compression_level_input) <= 9 else 0
        print(f"Уровень сжатия установлен на {compression_level}.")

        delete_original_input = input("Удалить оригинальные файлы после шифрования? (0 - нет, 1 - да): ").strip()
        delete_original = delete_original_input == '1'
        print(f"Оригинальные файлы будут {'удалены' if delete_original else 'сохранены'}.")

        # Вызываем процесс шифрования
        process_directory(
            directory=target_directory,          # Путь для обработки
            key=key,                              # Ключ шифрования
            key_number=key_number,                # Номер ключа
            decrypt=False,                        # Режим шифрования
            compression_level=compression_level,  # Уровень сжатия
            delete_original=delete_original       # Удаление оригинальных файлов
        )

    elif mode == '2':
        # Проверяем наличие ключей в указанной директории
        keys = list_keys(target_directory)
        if not keys:
            print("Ошибка: В указанной директории нет файлов ключей (.key).")
            key_directory = input("Введите путь к директории с ключами: ").strip()
            if not key_directory or not os.path.isdir(key_directory):
                print("Ошибка: Указанная директория с ключами не существует.")
                return

            keys = list_keys(key_directory)
            if not keys:
                print("Ошибка: В указанной директории с ключами нет файлов ключей (.key).")
                return

        # Если есть несколько ключей, вызываем функцию выбора ключа
        if len(keys) > 1:
            print("Доступные ключи:")
            for i, key_file in enumerate(keys, start=1):
                try:
                    key, decrypted_path = load_key(key_directory if 'key_directory' in locals() else target_directory, key_file)
                    print(f"{i}. {key_file} - Путь: {decrypted_path}")
                except Exception as e:
                    print(f"{i}. {key_file} - Ошибка загрузки пути: {e}")

            key_choice = input("Выберите номер ключа для дешифрования: ").strip()
            if not key_choice.isdigit() or int(key_choice) < 1 or int(key_choice) > len(keys):
                print("Неверный выбор ключа.")
                return

            key_file = keys[int(key_choice) - 1]
        else:
            key_file = keys[0]

        try:
            key, decrypted_path = load_key(key_directory if 'key_directory' in locals() else target_directory, key_file)
            key_number = int(key_file.split('.')[1])  # Извлекаем номер ключа из имени файла
            print(f"Загружен ключ шифрования: {key_file}")
            print(f"Путь обработки: {target_directory}")

            # Вызываем процесс дешифровки
            process_directory(
                directory=target_directory,  # Путь для обработки
                key=key,                      # Ключ шифрования
                key_number=key_number,        # Номер ключа
                decrypt=True                  # Режим дешифрования
            )
        except Exception as e:
            print(f"Ошибка при работе с ключом: {e}")

if __name__ == "__main__":
    main()