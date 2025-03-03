# Key Exchange Overiew from HSMs to AWS Payment Cryptography Service

Following diagrams illustrate at high level the process of key exchange using TR34 for initial bootstrapping and then key exchange using TR31 of working keys.

#### **TR-34 - Assymetric key exchange protocol to setup the KEK (Key Exchange Key) in AWS Payment Cryptography Service**
![TR-34 Flow - DUKPT](../../flows/apc-key-exchange-sequence-diagram-TR34.png)

#### **TR-31 - Symmetric key exchange protocol to setp working keys (PEK, PVK, PGK etc)**
![TR-34 Flow - DUKPT](../../flows/apc-key-exchange-sequence-diagram-TR31.png)
