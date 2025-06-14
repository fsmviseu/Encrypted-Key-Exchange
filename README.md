# CPS-Project---Encrypted-Key-Exchange

This repository consists of the code used in our project for the Course **Cryptography and Security Protocols**, by professor João Ribeiro. 

We provide a implementation of Bellovin and Merritt's EKE scheme in python, using RSA as the symmetric cipher.

Furthermore, we implement a Proof of Concept of Bellovin and Merritt's EKE scheme using Diffie-Hellman as the symmetric cipher. Furthermore, we implement some of the attacks mentioned in our chosen paper.

# Steps to run the project

1. Install dependencies using pipenv (only in the first time starting the project)

```bash
pipenv install
pipenv run pip install -e .
```

2. Run the server

```bash
pipenv shell
eke --debug server --protocol rsa/dh --host 127.0.0.1 --port 9999
```

3. Run the MITM server

```bash
pipenv shell
eke --debug mitm --protocol rsa/dh --host 127.0.0.1 --port 8888 --server-host 127.0.0.1 --server-port 9999
```

4. Run the Client against the Server

```bash
pipenv shell
eke --debug client --protocol rsa/dh --host 127.0.0.1 --port 9999
```

5. Run the Client against the MITM server

```bash
pipenv shell
eke --debug client --protocol rsa/dh --host 127.0.0.1 --port 8888
```