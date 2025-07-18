# Import Export Migration Scripts
**Note**: Currently supports payShield and Futurex HSMs

## Assumptions
KDH : Key Distribution Host
KRD : Key Receiving Device
Futurex : HSM is configured using PMK

## Configure AWS credentials
AWS credentials needed for the scripts can be configured in 2 ways :
* Configure environment variables for credentials : https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html
** To do this, leave 'assume_role' key in input_config.json file empty for 'apc' in either 'krd' or 'kdh' section.
* Use an IAM role to assume.
** To do this, add the IAM role arn to assume in 'assume_role' key in input_config.json file for 'apc' in either 'krd' or 'kdh' section.
** Configure environment variables for credentials for the account which will be used to assume this role. Make sure to add the calling account in the trust relationship of the assuming account.

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
python3 import_export_ecdh.py --kdh <Options: "futurex | payshield | apc"> --krd <Options: "apc">
```

To transport a key from 1 APC account to another APC account, add 'assume_role' of Account1 in 'apc' section of 'kdh' and 'assume_role' of Account2 in 'apc' section of 'krd'.
Configure environment variables for credentials of the central account with trust relationships added both in Account1 and Account2.
Central account credentials will be used to assume roles in Account1 and Account2.


