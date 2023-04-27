from cryptenv.utils.env_file import validate_encrypted_variable


def test_validate_encrypted_variable_empty():
    assert validate_encrypted_variable("") == (None, None)


def test_validate_encrypted_variable_valid():
    assert validate_encrypted_variable("$CRYPTENV;0.1;AES256$292102763") == ("0.1", "292102763")
