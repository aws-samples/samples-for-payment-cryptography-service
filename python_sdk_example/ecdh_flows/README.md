# AWS Payment Crypto ECDH Pin Set/Reveal flows

This repository contains a sample for three specific AWS Payment Cryptography Use Cases:
1. RESET PIN: When a user forgets it's PIN and you want to randomly generate a new one and show it to them, storing the PVV on the backend. 
2. SET PIN: When a user wants to set an arbitrary PIN, and the backend stores the PVV.
3. REVEAL PIN: When you want to obtain the pinblock from an encrypted pinblock for some very niche and specific use-cases

These use cases are implemented using ECDH Key Agreement to derive a symmetric key which is used to encrypt the pinblock between the device and AWS Payment Cryptography using ISO_FORMAT_4. As part of the implementation a Certificate Authority is needed, this demo implements it using AWS Private CA with short-lived certificates. 

## Flows
### Reset PIN
![PIN Reset](images/PIN-Reset.png?raw=true "PIN Reset")

### Select PIN
![PIN Select](images/PIN-Select.png?raw=true "PIN Select")

### Reveal PIN
![PIN Reveal](images/PIN-Reveal.png?raw=true "PIN Reveal")

## Cost
The following costs represent the us-east-1 (North Virginia) AWS Region, prices may vary across regions.

1. AWS Private CA for short-lived certificates has a pricing of US$ 50 (hourly prorated) per month.
2. AWS Private CA charges 0.058 for each short-lived certificate (This demo issues 4 certificates: 1 for CA setup, 1 for each flow)
3. Each AWS Payment Cryptography key is charged US$ 1 per key (hourly prorated) per month, and this demo uses 4 keys
4. Each AWS Payment Cryptography API is charged at US$ 2 per 10,000 API Calls, this demo does less than 50

You can stop the costs by calling the tear_down.py script included, which deletes all created assets.

If you execute this demo and immediately call tear_down.py, it will have an overall cost of 0.24 USD approximated.

## Setup

Generate a Python Virtual Environment and install required libraries
```
python3 -m venv .venv
pip3 install -r requirements.txt
```
You also need local AWS Credentials that have access to AWS Payment Cryptography and AWS Private CA

## Execute
Simulate the three flows of this Demo. This will create a Private CA and the needed AWS Payment Cryptography cryptographic key the first time is ran.
These keys and CA will stay created until you call the tear_down.py script.

```
python3 payment_crypto/main.py
```

## Clean Up
Clean up resources (including CA)
```
python3 payment_crypto/tear_down.py
```

