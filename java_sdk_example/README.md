# Payment Cryptography Service Samples

These JAVA samples are to show payment flows supported by [`AWS Payment Cryptography`](https://aws.amazon.com/payment-cryptography/).

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

There are samples for 2 flows below. The flows are setup on simulated terminal such as store terminal that processes payment or ATM that can be used for pin setup or pin verification.

```
aws.sample.paymentcryptography.terminal.PaymentTerminal
```

This class is setup for P2PE flow and uses pre created DUKPT to encrypt data from PaymentTerminal to send to Payment Processor API endpoint.
The test data is defined on [key-ksn-data.json](src/main/java/aws/sample/paymentcryptography/p2pe/key-ksn-data.json) file. For every increment of KSN counter (last 2 digits of KSN), a corresponding DUKPT has been pre-created.

To run - 

- cd `samples-for-payment-cryptography-service/java_sdk_example`
- Start the server which runs `PaymentProcessorService`
  - `./run_example.sh aws.sample.paymentcryptography.Application`
- Run the `PaymentTerminal`
    - `./run_example.sh aws.sample.paymentcryptography.terminal.PaymentTerminal`

```
aws.sample.paymentcryptography.terminal.PinTerminal
```

This class is setup for 2 flows 1/new pin setup, 2/ pin verification. 
These flows are setup for both `PEK` (where `PinTerminal` such as bank's ATM) directly talks to issuer and `DUKPT` (where `PinTerminal` such as thrid party ATM) connects with Payment Service PIN translator (`PaymentProcessorPinTranslateService`) which then connects to the `IssuerService`

The PEK based flow is - `PinTerminal` -> `IssuerService`.

The DUKPT based flow is - `PinTerminal` ->  `PaymentProcessorPinTranslateService` -> `IssuerService`.

In reas scenario, only DUKPT or PEK based flow would exist based on the type of service for pin sertup/verify.

To run - 
- cd `samples-for-payment-cryptography-service/java_sdk_example`
- Start the server which runs `PaymentProcessorService`
  - `./run_example.sh aws.sample.paymentcryptography.Application`
- Run the `PinTerminal`
    - `./run_example.sh aws.sample.paymentcryptography.terminal.PinTerminal`

## Helper classes
Following are helper classes to support the flows defined above. 

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
