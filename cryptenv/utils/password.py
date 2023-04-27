import os
import pathlib
import sys
from getpass import getpass
from typing import Union

from cryptenv.utils import exit_codes


def get_password(interactive: bool, verify: bool, passfile: pathlib.Path):
    if interactive:
        password = read_password_interactive(verify)
    elif passfile:
        password = read_password_file(passfile)
        if not password:
            print(f"Error reading password from {passfile.resolve()}")
            sys.exit(exit_codes.ERROR_READING_PASSWORD_FILE_CLI)
    else:
        env_file = os.getenv('CRYPTENV_PASSWORD_FILE')
        if not env_file:
            print("CRYPTENV_PASSWORD_FILE is not set")
            sys.exit(exit_codes.PASSWORD_FILE_ENV_NOT_SET)
        password = read_password_file(passfile)
        if not password:
            print(f"Error reading password from {env_file}")
            sys.exit(exit_codes.ERROR_READING_PASSWORD_FILE_ENV)
    return password


def read_password_interactive(verify: bool = False) -> str:
    if verify:
        attempts = 0
        while attempts < 3:
            password = getpass('Password: ')
            verify_password = getpass('Verify password: ')
            if verify_password == password:
                return password
            print('Password verification failed')
        print('Exiting because of 3 failed attempts to verify password')
        sys.exit(exit_codes.PASSWORD_VALIDATION_FAILED)
    password = getpass('Password: ')
    return password


def read_password_file(path: pathlib.Path) -> Union[str, None]:
    with open(path.resolve(), mode='r', encoding='utf-8', errors='strict') as f:
        lines = f.readlines()
        lines = [line for line in lines if line.strip() != ""]
        if len(lines) == 1:
            return lines[0]
    return None
