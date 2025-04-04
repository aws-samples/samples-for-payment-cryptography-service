# Import Export Migration Scripts
**Note**: Currently supports payShield and Futurex HSMs

## Assumptions
KDH : Key Distribution Host
KRD : Key Receiving Device
Futurex : HSM is configured using PMK

## Key Exchange using TR34

The script will establish a KEK (Key Encryption Key) between the chosen KDH and KRD. A set of options are supported for KDH and KRD type.
Update the input_config.json file with details on the host connection.
If KDH or KRD is AWS Payment Cryptography, update the region and/or endpoint you would like to connect to.
If KDH or KRD is Futurex or payShield HSM, update the host ip address and port that you would like to stablish the connection to.

As part of the key exchange, if you would like to generate a new symmetric KEK, leave 'transport_key' and 'transport_key_kcv' in the config file for KDH as blank.
If you already have a key created, update the key and kcv in the config file for KDH.

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

### Key Exchange using ECDH
The script will perform key agreement using ECDH between KDH and KRD, derive a shared key which will be the KEK to wrap the transport key.
Using this path, you can import/export upto AES-256 keys.

### Usage

```
python3 src/import_export/import_export_ecdh.py --kdh <Options: "futurex | payshield | apc"> --krd <Options: "apc">
```
