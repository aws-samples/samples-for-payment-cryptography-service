## AWS Payment Cryptography Samples

This repos contains samples for AWS Payment Cryptography for - key import, P2PE and Pin (set and verify) flows.

### Key Import
The samples are setup to run based on keys in the [key import app](key-import/import_files/apc_demo_keysetup.py). As a first step, you will need to run the key import app. Refer to [key import instructions](key-import/import_files/Readme.md)

### Point-to-point encryption (P2PE)
This is simulated by [Payment Terminal Client](java_sdk_example/src/main/java/aws/sample/paymentcryptography/terminal/PaymentTerminal.java) which connects to [Payment Processor Service](java_sdk_example/src/main/java/aws/sample/paymentcryptography/p2pe/PaymentProcessorService.java). Refer to the [test data](java_sdk_example/src/main/java/aws/sample/paymentcryptography/p2pe/key-ksn-data.json) used by the terminal that contains DUKPT variant, track2 data and KSN. 

Following diagram illustrates the flow - 

![P2PE Flow](flows/PaymentCryptographyServiceFlows-Payment%20Terminal%20Flow%20-%20P2PE.jpg)

### PIN Flows
This is simulated by [Pin Terminal Client](java_sdk_example/src/main/java/aws/sample/paymentcryptography/terminal/PaymentTerminal.java). There are 2 flows setup on the client - 

#### Set Pin
In this flow, the [ATM](java_sdk_example/src/main/java/aws/sample/paymentcryptography/terminal/ATM.java) uses Pin Encryption Key set the PIN with the [Issuer](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/IssuerService.java) 

Following diagram illustrates the flow - 

##### Set PIN (PEK)
![Set PIN Flow - PEK](flows/PaymentCryptographyServiceFlows-Pin%20Terminal%20Set%20Pin%20Flow%20(PEK).jpg)

#### Verify Pin
In this flow, the [PinTerminal](java_sdk_example/src/main/java/aws/sample/paymentcryptography/terminal/PinTerminal.java) verifies the PIN via [Pin Translator](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/PaymentProcessorPinTranslateService.java) which uses [Issuer](java_sdk_example/src/main/java/aws/sample/paymentcryptography/pin/IssuerService.java).  

Following diagrams illustrate the flow - 
![Verify PIN Flow - DUKPT](flows/PaymentCryptographyServiceFlows-Pin%20Terminal%20Pin%20Verification%20Flow%20(DUKPT).jpg)

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.