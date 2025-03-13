# AWS Payment Cryptography Samples

This repo contains samples for AWS Payment Cryptography (APC) for - 
- key exchange between APC with HSMs such as [Payshield](key-import-export/key_exchange/), [Atalla](key-import-export/key_exchange/hsm/atalla/) and [Futurex](key-import-export/key_exchange/) using TR-34 and TR-31 protocols. Alternatively, for testing, you can also import plain text keys using either [TR-34](key-import-export/tr34/) or [RSA](key-import-export/rsa/).
- Various payment flow such as P2PE, Pin (set and verify) and Pin translation and ECDH Pin Set/Reveal

Before starting, ensure that the [service is available in the region](https://aws.amazon.com/payment-cryptography/pricing/) you want to run the samples in.

## Samples

### [Key Import/Export](key-import-export/)
This section contains Python based script to exchange keys between APC and HSMs such as [Payshield](key-import-export/key_exchange/README.md), [Atalla](key-import-export/key_exchange/hsm/atalla/readme.md) and [Futurex](key-import-export/key_exchange/README.md). Alternatively, for testing, you can also import plain text keys using either [TR-34](key-import-export/tr34/import_app/Readme.md) or [RSA](key-import-export/rsa/import_app/import_raw_key_into_apc_with_rsa_wrap.py) into APC.

Before running the sample [JAVA](java_sdk_example/README.md) or [Python](python_sdk_example/ecdh_flows/README.md) based application, you will need to import the required keys into AWS Cryptography Service. 


### [JAVA Based Flows](java_sdk_example/README.md)
This section contains flows such as P2PE, Pin set/verify and translation. Additionally, the flows are implemented using both [synchronous](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/IssuerService.java) and [asynchronous](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/AsyncIssuerService.java) APIs showing flexibility of APC.

### [Python Based Flows](python_sdk_example/)
This section contains ECDH flow for pin set and pin reveal functionalities

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.