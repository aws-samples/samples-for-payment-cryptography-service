## AWS Payment Cryptography Samples

This repos contains samples for AWS Payment Cryptography for - key import, P2PE and Pin (set and verify) flows.

Before starting, ensure that the [service is available in the region](https://aws.amazon.com/payment-cryptography/pricing/) you want to run the samples in.
dfgsdfg
### Flows

#### Key Import (Pre Requisite)
Before running the sample application, you will need to import the required keys into AWS Cryptography Service. The samples are setup to run based on keys that will get imported thru the [key import app](key-import-export/tr34/import_app/apc_demo_keysetup.py). Refer to [key import instructions](key-import-export/tr34/import_app/Readme.md).<br>

After importing the keys, refer to [readme](java_sdk_example/README.md) to run the samples.

#### Point-to-point encryption (P2PE)
This is simulated by [Payment Terminal Client](java_sdk_example/src/main/java/aws/sample/paymentcryptography/terminal/PaymentTerminal.java) which connects to [Payment Processor Service](java_sdk_example/src/main/java/aws/sample/paymentcryptography/p2pe/PaymentProcessorService.java). Refer to the [test data](java_sdk_example/test-data/sample-key-ksn-data.json) used by the terminal that contains DUKPT variant, track2 data and KSN. 

Following diagram illustrates the flow - 

![P2PE Flow](flows/PaymentCryptographyServiceFlows-Payment%20Terminal%20Flow%20-%20P2PE.jpg)

#### PIN Flows
This is simulated by [Pin Terminal Client](java_sdk_example/src/main/java/aws/sample/paymentcryptography/terminal/PaymentTerminal.java). There are 2 flows setup on the client - 

##### Set Pin
In this flow, the [ATM](java_sdk_example/src/main/java/aws/sample/paymentcryptography/terminal/ATM.java) uses Pin Encryption Key (PEK) to set the PIN with [Issuer](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/IssuerService.java) 

Following diagram illustrates the flow - 

###### Set PIN (PEK)
![Set PIN Flow - PEK](flows/PaymentCryptographyServiceFlows-Pin%20Terminal%20Set%20Pin%20Flow%20(PEK).jpg)

##### Verify Pin
In this flow, the [PinTerminal_ISO_Format_0](java_sdk_example/src/main/java/aws/sample/paymentcryptography/terminal/PinTerminal_ISO_0_Format.java) or [PinTerminal_ISO_Format_4](java_sdk_example/src/main/java/aws/sample/paymentcryptography/terminal/PinTerminal_ISO_4_Format.java) verifies the PIN via [Pin Translator](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/PaymentProcessorPinTranslateService.java) which connect to [Issuer](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/IssuerService.java) for verification.

Following diagrams illustrate the flow - 
![Verify PIN Flow - DUKPT](flows/PaymentCryptographyServiceFlows-Pin%20Terminal%20Pin%20Verification%20Flow%20(DUKPT).jpg)

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
