import sys
from packaging import version
from typing import Final

from cryptenv.utils.exit_codes import UNSUPPORTED_PYTHON_VERSION

PYTHON_MIN_VERSION: Final[str] = "3.9"
CRYPTENV_VERSION: Final[str] = "0.2"


def print_version(raw: bool) -> None:
    if (raw):
        print(CRYPTENV_VERSION)
    else:
        print(CRYPTENV_VERSION + " blah")


def check_python_version() -> None:
    python_version = str(sys.version_info[0]) + '.' + str(sys.version_info[1])
    if version.parse(python_version) < version.parse(PYTHON_MIN_VERSION):
        sys.exit(UNSUPPORTED_PYTHON_VERSION)


def check_variable_version(variable_version: str) -> bool:
    if version.parse(variable_version).major != version.parse(CRYPTENV_VERSION).major:
        return False
    return True
