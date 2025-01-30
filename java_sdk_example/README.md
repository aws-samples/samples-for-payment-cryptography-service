# Payment Cryptography Service Samples

These JAVA samples are to show payment flows supported by [`AWS Payment Cryptography`](https://aws.amazon.com/payment-cryptography/).

Please ensure you have Java 17 or higher.

## Instructions

### Install Maven

The samples need Maven to run. You can install it from https://maven.apache.org/install.html if not already installed on your system.

### Build the samples app 

cd samples-for-payment-cryptography-service/java_sdk_example

```
mvn clean install
```

In both cases the clean step is unnecessary if it's the first time you're building it.

### Set up your creds

The examples pull your AWS credentials from environment variables or your credentials file. If using environment variables, you can exporrt them like below :

```
export AWS_ACCESS_KEY_ID=ASIA....
export AWS_SECRET_ACCESS_KEY=abcd....
export AWS_SESSION_TOKEN=wxyz....
```

### Run the examples

There are samples for 2 flows below. The flows are setup on simulated terminals such as store terminal that processes payment or ATM that can be used for pin setup or PIN terminal that does PIN verification. Prior to running the samples, you will need to start the server like below. 
The server has services that the terminals connect to support the flows.

***Note:***
- Intentional delays are added between each transactions (using `Thread.sleep`) in [PaymentTerminal](src/main/java/aws/sample/paymentcryptography/terminal/PaymentTerminal.java), [ATM](src/main/java/aws/sample/paymentcryptography/terminal/ATM.java),[PinTerminal_ISO_Format_0](src/main/java/aws/sample/paymentcryptography/terminal/PinTerminal_ISO_0_Format.java) and [PinTerminal_ISO_Format_4](src/main/java/aws/sample/paymentcryptography/terminal/PinTerminal_ISO_4_Format.java) to make it easier to follow the flows.

- For simplicity, the APIs in samples are implemented with HTTP GET. This would not apply in production.*

#### Pre Requisite
The samples are setup to run based on keys in the [key import app](../key-import-export/import_app/apc_demo_keysetup.py). As a pre-requisite, you will need to run the key import app. Refer to [key import instructions](../key-import-export/import_app/Readme.md)

#### Starting the Server
```
cd samples-for-payment-cryptography-service/java_sdk_example
./run_example.sh aws.sample.paymentcryptography.Application

```

#### [PaymentTerminal](src/main/java/aws/sample/paymentcryptography/terminal/PaymentTerminal.java)

This class is setup for P2PE flow and uses pre created DUKPT to encrypt data from [PaymentTerminal](src/main/java/aws/sample/paymentcryptography/terminal/PaymentTerminal.java) to send to Payment Processor API endpoint.
The test data is defined on [key-ksn-data.json](/java_sdk_example/test-data/sample-pek-ksn-data.json) file. For every increment of KSN counter (last 2 digits of KSN), a corresponding DUKPT has been pre-created.

To run - 

```
cd samples-for-payment-cryptography-service/java_sdk_example
./run_example.sh aws.sample.paymentcryptography.terminal.PaymentTerminal
```

#### [ATM](src/main/java/aws/sample/paymentcryptography/terminal/ATM.java)

This is a simulation of [ATM](src/main/java/aws/sample/paymentcryptography/terminal/ATM.java) that sets PIN through an Issuer. It uses pre setup [PIN](/java_sdk_example/test-data/sample-pin-pan.json) test
data to create an encoded PIN block and encrypts that block using pre setup PEK. The encrypted data is then sent to the [issuer](src/main/java/aws/sample/paymentcryptography/pin/IssuerService.java) to set the PIN.

To run - 

```
cd samples-for-payment-cryptography-service/java_sdk_example
./run_example.sh aws.sample.paymentcryptography.terminal.ATM

```
#### PinTerminals

There are 2 variations of Pin terminals. Both of these create the encrypted PIN block along with [ARQC cryptogram](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/data-operations.verifyauthrequestcryptogram.html) for pin authorization flow.

- [PinTerminal using ISO 0 Format for Pin Encryption](src/main/java/aws/sample/paymentcryptography/terminal/PinTerminal_ISO_0_Format.java)

  This class simulates terminal encrypting a plain text PIN using [ISO 0 Format](https://en.wikipedia.org/wiki/ISO_9564#Format_0) for PIN encryption. 

- [PinTerminal using ISO 4 Format for Pin Encryption](src/main/java/aws/sample/paymentcryptography/terminal/PinTerminal_ISO_4_Format.java)

  This class simulates terminal encrypting a plain text PIN using [ISO 4 Format](https://listings.pcisecuritystandards.org/documents/Implementing_ISO_Format_4_PIN_Blocks_Information_Supplement.pdf) for PIN encryption.
  
     
Both classes above are a simulation of a terminal that accepts PIN and transaction and sends it for authorization. It uses pre setup PIN data to create an encoded PIN block and encrypts that block using pre setup keys in [PEK data for ISO Format 0 ](/java_sdk_example/test-data/sample-pek-ksn-data-iso-0-format.json), [PEK data for ISO Format 4 ](/java_sdk_example/test-data/sample-pek-ksn-data-iso-4-format.json) and [ARQC key and transaction data](/java_sdk_example/test-data/sample-pan-arqc-key.json). 

The DUKPT encrytion keys in [PEK data for ISO Format 0 ](/java_sdk_example/test-data/sample-pek-ksn-data-iso-0-format.json) and [PEK data for ISO Format 4 ](/java_sdk_example/test-data/sample-pek-ksn-data-iso-4-format.json) are derived off of the BDK defined in [apc_demo_keysetup.py](../key-import-export/tr34/import_app/apc_demo_keysetup.py) BDK variable.

The ARQC UDK (Unique Derived Key) is derived from the MDK (Master Derivation Key) defined in [apc_demo_keysetup.py](../key-import-export/tr34/import_app/apc_demo_keysetup.py) ARQC variable, PAN and Pan Sequence Number (PSN) with value `00`. If PSN hasn't been set, the default is typically 00. ARQC is generated using Amex CVN01 which uses EMV Derivation Method A.

***Note:** Derivation of DUKPT and ARQC keys used in the terminals are out of scope for provided samples. You can refer to [Payment Card Tools](https://paymentcardtools.com/) for reference.*

The classes are setup for 2 flows 1/new pin setup, 2/ pin authorization. The encrypted data is then sent to the [PIN translating service](src/main/java/aws/sample/paymentcryptography/pin/PaymentProcessorPinTranslateService.java) which translates the encrypted pin blocks according to the incoming and outgoing ISO formats then connects to the [Issuer](src/main/java/aws/sample/paymentcryptography/pin/IssuerService.java) to verify the PIN.

To run - 

```
cd samples-for-payment-cryptography-service/java_sdk_example
./run_example.sh aws.sample.paymentcryptography.terminal.PinTerminal_ISO_0_Format
```

OR

```
cd samples-for-payment-cryptography-service/java_sdk_example
./run_example.sh aws.sample.paymentcryptography.terminal.PinTerminal_ISO_4_Format
```

## Helper classes
Following are additional helper classes for reference only.

#### CreateAlias

This will create an alias, either with a name you provide or a random one if you don't specify anything. The main purpose of this is to demonstrate basic operations against the API.

`./run_example.sh aws.sample.paymentcryptography.CreateAlias` or `./run_example.sh aws.sample.paymentcryptography.CreateAlias "alias/testalias-abcde"`

#### ListAliases

This will list all the aliases in your account, plus what key they point to (if any).

The main purpose of this example is to let you inspect your resources and see how pagination works.

`./run_example.sh aws.sample.paymentcryptography.ListAliases`

#### ListKeys

This will list all the keys in your account, with a bit of info about each one's type. 

The main purpose of this example is to let you inspect your resources and see how pagination works, as well as show some ways in which interacting with keys is different than interacting with aliases (for example, the attributes are nested more deeply, and ListKeys only returns the ARN, not all the info about the object, so an additional GetKey call is necessary).

`./run_example.sh aws.sample.paymentcryptography.ListKeys`
