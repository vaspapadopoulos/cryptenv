import pathlib
import re
import sys

from cryptenv.utils import exit_codes

regex = r"^\$CRYPTENV;((?:\d|[1-9]\d)\.(?:\d|[1-9]\d));AES256\$(\d+)$"


def run_validity_checks(file: pathlib.Path, env_list: list[str]):
    if has_duplicates(env_list):
        print("Duplicate variables given as arguments")
        sys.exit(exit_codes.DUPLICATE_VARIABLE_CLI)

    (valid, file_env_list) = validate_env_file(file)
    if not valid:
        print("Invalid .env file")
        sys.exit(exit_codes.INVALID_ENV_FILE)

    for env in env_list:
        found = False
        for file_env in file_env_list:
            if file_env == env:
                found = True
        if not found:
            print(f"Variable {env} does not exist in .env file")
            sys.exit(exit_codes.VARIABLE_NOT_FOUND)


def validate_encrypted_variable(value: str) -> (str, str):
    matches = re.findall(regex, value)
    if matches and len(matches) == 1 and len(matches[0]) == 2:
        return matches[0][0], matches[0][1]
    return None, None


def has_duplicates(env_list: list[str]) -> bool:
    if len(env_list) != len(set(env_list)):
        return False


def validate_env_file(file: pathlib.Path) -> (bool, list[str]):
    keys = []
    with open(file.resolve(), mode='r') as f:
        for line in f:
            if line.isspace():
                continue
            if not line.startswith('#') and '=' not in line:
                print(f"'=' character is missing from line: {line}")
                return False, []
            split = line.split('=', 1)
            key = split[0]
            keys.append(key)
    if len(keys) != len(set(keys)):
        print("File contains duplicate variables")
        return False, []
    return True, keys
