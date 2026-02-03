# AWS Payment Cryptography Samples

This repo contains sample code for AWS Payment Cryptography Service for - 
- key exchange between AWS Payment Cryptography with HSMs such as [payShield 10k](key-import-export/key_exchange/), [Atalla AT1000](key-import-export/key_exchange/hsm/atalla/) and [Futurex](key-import-export/key_exchange/) using TR-34 and TR-31 protocols.
- Various payment flow such as P2PE, Pin (set and verify) and Pin translation and ECDH Pin Set/Reveal

Before starting, ensure that the [service is available in the region](https://aws.amazon.com/payment-cryptography/pricing/) you want to run the samples in.

## Samples

### [Key Import/Export](key-import-export/)
This section contains Python based script to exchange keys between AWS Payment Cryptography Service and HSMs such as [payShield 10k](key-import-export/key_exchange/README.md), [Atalla AT1000](key-import-export/key_exchange/hsm/atalla/readme.md) and [Futurex](key-import-export/key_exchange/README.md). This process can be used for either key migration or for ongoing synchronization.
Alternatively, for testing, you can also import plain text keys using either [TR-34](key-import-export/tr34/import_app/Readme.md) or [RSA](key-import-export/rsa/import_app/import_raw_key_into_apc_with_rsa_wrap.py) into AWS Payment Cryptography.

#### Prerequisite
Before running the [JAVA](java_sdk_example/README.md) or [Python](python_sdk_example/ecdh_flows/README.md) based sample applications, you will need to import the required keys into AWS Payment Cryptography. Refer to [instructions](key-import-export/tr34/import_app/Readme.md) for importing plain text keys before running the sample applications. **Note: This should be used in non-production testing environment only.**


### [JAVA Based Flows](java_sdk_example/README.md)
This section contains flows such as P2PE, Pin set/verify and translation. Additionally, the flows are implemented using both [synchronous](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/IssuerService.java) and [asynchronous](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/AsyncIssuerService.java) APIs showing flexibility of AWS Payment Cryptography.

**New Features:**
- **ARPC (Authorization Response Cryptogram)** support is now available, providing cryptographic proof of issuer authorization decisions. See the [ARPC Implementation Guide](java_sdk_example/ARPC_IMPLEMENTATION.md) for details.
- **ECDH PIN Exchange** implementation demonstrating secure PIN operations using Elliptic Curve Diffie-Hellman key agreement. See the [ECDH Implementation Guide](java_sdk_example/ECDH_README.md) for details.

### [Python Based Flows](python_sdk_example/ecdh_flows/README.md)
This section contains ECDH flow for pin set and pin reveal functionalities

### [Golang Based ECDH Use Cases](go_sdk_example/ecdh-use-cases/README.md)
This section contains ECDH sample use cases

### [Golang Based Key Import/Export](go_sdk_example/key-import-export/tr34/README.md)
This section contains Golang based sample code to import/export keys using TR-34 or TR-31 protocols

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.