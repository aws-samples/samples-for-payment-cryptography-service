# Import Export Migration Scripts
**Note**: Currently supports payShield and Futurex HSMs.  Running TR-34, ECDH and RSA wrap commands relies on access to host (not admin) modules of HSM.  HSM admin consoles do not typically expose this functionality.


## Assumptions
* KDH : Key Distribution Host
* KRD : Key Receiving Device
* Futurex : HSM is configured using PMK. Tested using firmware versions [7.4, 7.6].
* payShield: Tested using firmware versions [1.14].

## Key Exchange using TR34

The script will establish a KEK (Key Encryption Key) between the chosen KDH and KRD. A set of options are supported for KDH and KRD type.
Update the input_config.json file with details on the host connection.
If KDH or KRD is AWS Payment Cryptography, update the region and/or endpoint you would like to connect to.
If KDH or KRD is Futurex or payShield HSM, update the host ip address and port that you would like to stablish the connection to.

As part of the key exchange, if you would like to generate a new symmetric KEK, leave 'transport_key' and 'transport_key_kcv' in the config file for KDH as blank.
If you already have a key created, update the key and kcv in the config file for KDH.

### Commands used when transferring with a payShield
* payShield - EI (create RSA key), B8(export key using TR-34), A0 (create symmetric key, optional only if key to export isn't specified)
* Payment Cryptography - Get Parameters for import, Import Key (KeyMaterial=Tr34KeyBlock), Import Key (type=RootCertificatePublicKey), Import Key (type=TrustedPublicKey, optional only for intermediate CA)
* NOTE: This sample code uses a certificate authority (CA) within the sample code. For production use, we recommend using your own CA or AWS Private Certificate Authority (PCA).
* 
### Usage

* Establish the connection to your chosen Payment HSM and update input config file with host and port info to connect.
* Set AWS credentials for the account you want to use for the service resources. Set the region you want to execute the scripts in input config.

```
python3 import_export_tr34.py --kdh <Options: "futurex | payshield"> --krd <Options: "apc">
```

## Key Exchange using TR31
The script will exchange working keys between KDH and KRD once a KEK is established between KDH and KRD.
Establish a KEK using the Tr34 script and update the kek in the input_config file for both KDH and KRD.

As part of the key exchange, if you would like to generate a new symmetric KEK, leave 'transport_key' and 'transport_key_kcv' in the config file for KDH as blank.
If you already have a key created, update the key and kcv in the config file for KDH.


  
### Usage

* Establish the connection to your chosen Payment HSM and update input config file with host and port info to connect.
* Set AWS credentials for the account you want to use for the service resources. Set the region you want to execute the scripts in input config.

```
python3 import_export_tr31.py --kdh <Options: "futurex | payshield"> --krd <Options: "apc">
```

## Key Exchange using ECDH
The script will perform key agreement using ECDH between KDH and KRD, derive a shared key which will be the KEK to wrap the transport key.
Using this path, you can import/export upto AES-256 keys.

### Commands used when transferring with a payShield
* Ensure that all commands/APIs are enabled on both HSM and Payment Cryptography side.
* payShield - FY (create ECC key), IG(derive key using ECDH), A8 (export key using TR-31), A0 (create symmetric key, optional only if key to export isn't specified), authorized activty = eckai.K1.host (enable using ECDH to generate Key Block Protection Keys)
* Payment Cryptography - Create Key (ECC type), Get Public Key Certificate, Import Key (KeyMaterial=DiffieHellmanTr31KeyBlock), Import Key (type=RootCertificatePublicKey), Import Key (type=TrustedPublicKey, optional only for intermediate CA)
* NOTE: This sample code uses a certificate authority (CA) within the sample code. For production use, we recommend using your own CA or AWS Private Certificate Authority (PCA).

### Usage

```
python3 import_export_ecdh.py --kdh <Options: "futurex | payshield | apc"> --krd <Options: "apc">
```
