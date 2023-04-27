# cryptenv

[![Python](https://img.shields.io/badge/Python-3.9-3776AB.svg?logo=python)](https://www.python.org/)

A Python-based CLI to encrypt and decrypt variables in `.env` files.

## Installation


## Usage


### Examples

Encrypt and decrypt a single variable in a `.env` file:

```shell
cryptenv.py encrypt -f .env.myproject PASSWORD
cryptenv.py decrypt -f .env.myproject API_TOKEN
```

Encrypt all variables in a `.env` file:

```shell
cryptenv.py encrypt -f .env.myproject --all
```

Decrypt all encrypted variables, if any, in a `.env` file:

```shell
cryptenv.py decrypt -f .env.myproject
```
