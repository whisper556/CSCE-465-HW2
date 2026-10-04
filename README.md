# CSCE 465/765 – Homework 2

## Setup

Run from this directory (`hw2/`) inside the course VM.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

`ffdhe3072.pem` is included. To regenerate it (OpenSSL 3.0+):

```bash
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
```

## Run the demos

```bash
python3 baseline_ctr.py     # Task 1
python3 handshake.py        # Task 2
python3 secure_record.py    # Task 3
```

## Run the tests (Task 4)

```bash
python -m pytest -v
```

Expected: 73 passed (about 45 seconds). Keep `pytest.ini` in `hw2/`; it sets the import path.
