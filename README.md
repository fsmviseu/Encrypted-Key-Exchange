# CPS-Project---Encrypted-Key-Exchange

This repository consists of the code used in our project for the Course **Cryptography and Security Protocols**, by professor João Ribeiro. 

We provide a implementation of Bellovin and Merritt's EKE scheme in python, using RSA as the symmetric cipher.

Furthermore, we implement Bellovin and Merritt's EKE scheme using Diffie-Hellman as the symmetric cipher. We also implement some of the attacks mentioned in our chosen paper.

# Test run

[![Proof of Concept](./poc.mp4)]

# Steps to run the project

On 1-5, choose either `dh` - Diffie Hellman or `rsa`- RSA as the underlying KA. The `--debug` flag is optional.

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

6. Allowing Identity Element in Diffie-Hellman Attack

(in different terminal windows)

```bash
pipenv shell

eke  server --protocol dh
eke  mitm --protocol dh-vuln1
eke  client --protocol dh-vuln1

```

7. A Man-In-The-Middle attack for plain Diffie-Hellman

(in different terminal windows)

```bash
pipenv shell

eke  server --protocol dh
eke  mitm --protocol dh-vuln2
eke  client --protocol dh-vuln2

```
