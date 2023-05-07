import argparse
import hashlib
import os
import pathlib
import sys

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import cryptenv.utils.version
from cryptenv.actions.file import FileAction
from cryptenv.utils import exit_codes
from cryptenv.utils.env_file import run_validity_checks, validate_encrypted_variable
from cryptenv.utils.password import get_password
from cryptenv.utils.version import check_python_version, check_variable_version, print_version

check_python_version()

parser = argparse.ArgumentParser(description='Cryptenv argument parser.')

subparsers = parser.add_subparsers(required=True)

encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt variable(s) in .env file')
encrypt_password_group = encrypt_parser.add_mutually_exclusive_group(required=False)
encrypt_password_group.add_argument('-i', '--interactive',
                                    required=False,
                                    default=False,
                                    action='store_true',
                                    help='prompt for password')
encrypt_password_group.add_argument('-p', '--passfile',
                                    metavar='PASSWORD_FILE',
                                    type=pathlib.Path,
                                    required=False,
                                    nargs=argparse.OPTIONAL,
                                    action=FileAction,
                                    help='file containing password')
encrypt_parser.add_argument('-f', '--file',
                            metavar='ENV_FILE',
                            type=pathlib.Path,
                            required=True,
                            nargs=argparse.OPTIONAL,
                            action=FileAction,
                            help='the .env file to encrypt')

decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt variable(s) in .env file')
decrypt_password_group = decrypt_parser.add_mutually_exclusive_group(required=False)
decrypt_password_group.add_argument('-i', '--interactive',
                                    required=False,
                                    default=False,
                                    action='store_true',
                                    help='prompt for password')
decrypt_password_group.add_argument('-p', '--passfile',
                                    metavar='PASSWORD_FILE',
                                    type=pathlib.Path,
                                    required=False,
                                    nargs=argparse.OPTIONAL,
                                    action=FileAction,
                                    help='file containing password')
decrypt_parser.add_argument('-f', '--file',
                            metavar='ENV_FILE',
                            type=pathlib.Path,
                            required=True,
                            nargs=argparse.OPTIONAL,
                            action=FileAction,
                            help='the .env file to decrypt')

decrypt_parser = subparsers.add_parser('version', help='Show cryptenv version details')
decrypt_password_group = decrypt_parser.add_mutually_exclusive_group(required=False)
decrypt_password_group.add_argument('-r', '--raw',
                                    required=False,
                                    default=False,
                                    action='store_true',
                                    help='print version only')


def encrypt(password: str, file: pathlib.Path, env_list: list[str]) -> None:
    run_validity_checks(file, env_list)

    new_lines = []
    with open(file.resolve(), mode='r', encoding='utf-8', errors='strict') as f:
        for line in f:
            if not line.isspace() and not line.startswith('#') and '=' in line:
                split = line.split('=', 1)
                key = split[0]
                value = split[1]
                for env in env_list:
                    if env == key:
                        version, encrypted_value = validate_encrypted_variable(value)
                        if version and encrypted_value:
                            print(f"Variable {key} in .env file is already encrypted")
                            sys.exit(exit_codes.ALREADY_ENCRYPTED_VARIABLE)
                        encrypted_env = encrypt_env(value.strip(), password)
                        line = f"{key}=CRYPTENV;{cryptenv.utils.version.CRYPTENV_VERSION};AES256${encrypted_env}"
            new_lines.append(line)

    with open(file, 'w') as f:
        for line in new_lines:
            f.write(line)


def decrypt(password: str, file: pathlib.Path, env_list: list[str]) -> None:
    run_validity_checks(file, env_list)

    new_lines = []
    with open(file.resolve(), mode='r', encoding='utf-8', errors='strict') as f:
        for line in f:
            if not line.startswith('#') and '=' in line:
                split = line.split('=', 1)
                key = split[0]
                value = split[1]
                for env in env_list:
                    if env == key:
                        version, encrypted_value = validate_encrypted_variable(value)
                        if not version or not encrypted_value:
                            print(f"Invalid encryption payload for variable {key} in .env file")
                            sys.exit(exit_codes.INVALID_ENCRYPTED_PAYLOAD)
                        if not check_variable_version(version):
                            print(f"Variable {key} in .env file encrypted with unsupported cryptenv version: {version}")
                            sys.exit(exit_codes.UNSUPPORTED_CRYPTENV_VERSION)
                        decrypted_env = decrypt_env(encrypted_value, password)
                        line = f"{key}={str(decrypted_env)}"
            new_lines.append(line)

    with open(file, 'w') as f:
        for line in new_lines:
            f.write(line)


def encrypt_env(data: str, password: str) -> str:
    sha256 = hashlib.sha256()
    sha256.update(password.encode(encoding='utf-8', errors='strict'))
    key = sha256.digest()
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES256(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(256).padder()

    data_utf8 = data.encode(encoding='utf-8', errors='strict')
    data_padded = padder.update(data_utf8) + padder.finalize()
    data_encrypted = encryptor.update(data_padded) + encryptor.finalize()
    data_encrypted_repr = int.from_bytes(iv + encryptor.tag + data_encrypted, 'little')
    return str(data_encrypted_repr)


def decrypt_env(data: str, password: str) -> str:
    sha256 = hashlib.sha256()
    sha256.update(password.encode(encoding='utf-8', errors='strict'))
    key = sha256.digest()

    data_repr = int(data)
    data_bytes = data_repr.to_bytes((data_repr.bit_length() + 7) // 8, 'little')

    iv = data_bytes[:12]
    tag = data_bytes[12:28]
    encrypted_data = data_bytes[28:]
    cipher = Cipher(algorithms.AES256(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(256).unpadder()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode(encoding='utf-8', errors='strict')


def main():
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(exit_codes.NO_ARGUMENTS)

    args, envs = parser.parse_known_args(sys.argv[1:])

    if sys.argv[1] == "encrypt":
        password = get_password(args.interactive, True, args.passfile)
        encrypt(password=password, file=args.file, env_list=envs)
    elif sys.argv[1] == "decrypt":
        password = get_password(args.interactive, False, args.passfile)
        decrypt(password=password, file=args.file, env_list=envs)
    elif sys.argv[1] == "version":
        print_version(args.raw)


if __name__ == "__main__":
    main()
