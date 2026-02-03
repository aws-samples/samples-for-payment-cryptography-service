# AWS Payment Crypto ECDH Pin Set/Reveal flows

This repository contains a sample for three specific AWS Payment Cryptography Use Cases:
1. Generate CVV2/CSC
2. Validate CVV2/CSC

## Setup

Generate a Python Virtual Environment and install required libraries
```
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```
You also need local AWS Credentials that have access to AWS Payment Cryptography 

## Execute
```
python3 main.py
```

## Clean Up
Clean up created keys 
```
python3 payment_crypto/tear_down.py
```

