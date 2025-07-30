# AWS Payment Cryptography ECDH Use Cases

An example script using the [AWS Go SDK V2](https://github.com/aws/aws-sdk-go-v2) to display several use cases of the ECDH mechanism on AWS Payment Cryptography service.

## How to use it?

To use this script, simply execute the application with `go run .` plus some flags to select and control the use cases. The execution of each use case will be discussed in detail below, and to learn more about the available flags the `help` flag can be used:

```sh
go run . -h
```

If pulling the required libraries through Google's mirror [`proxy.golang.org`](https://proxy.golang.org) is not possible or bypassing it is desired, the following command can be used to opt-out and pull everything directly from source:

```sh
go env -w GOPROXY=direct
```

> 🚩 Executions of this script will leave at AWS Payment Cryptography any imported or generated keys, except 
> the ECC keys used to derive the single use symmetric key supporting each use case. Such keys that won't be
> deleted will have their ARN and KCV logged to STDOUT, take note of those to perform cleanup in a later moment
> if needed.

### Importing a clear transport key

To execute the clear transport key import use case, run:

```sh
# Imports an AES-256 clear key as a KBPK
go run . \
  -aws-profile YOUR_PROFILE_NAME_HERE \
  -use-case ImportClearTransportKey \
  -target-key-algorithm AES256 \
  -target-key 0000000000000000000000000000000000000000000000000000000000000000
```

Other algorithms are also available:

```sh
# Imports a TDES3key clear key as a KBPK
go run . \
  -aws-profile YOUR_PROFILE_NAME_HERE \
  -use-case ImportClearTransportKey \
  -target-key-algorithm TDES3Key \
  -target-key 000000000000000000000000000000000000000000000000
```

### Setting a new PIN for a card

To execute the PIN select use case, run:

> ℹ️ This will also create a PEK to protect the generated PIN block, and a PVK to generate the PIN Verification Value.

```sh
go run . \
  -aws-profile YOUR_PROFILE_NAME_HERE \
  -use-case PINSelect \
  -pin 2222 \
  -pan 1122334455667788
```

This use case can also be run with a pre-existing PEK and/or PVK; to do so, provide the alias or ARN using the respective flags:

```sh
# ARN example:    arn:aws:payment-cryptography:us-east-2:111122223333:key/abcd1234efgh5678
# alias example:  alias/some_key_alias
go run . \
  -aws-profile YOUR_PROFILE_NAME_HERE \
  -use-case PINSelect \
  -pin 2222 \
  -pan 1122334455667788 \
  -pek-id YOUR_PEK_ALIAS_OR_ARN \
  -pvk-id YOUR_PVK_ALIAS_OR_ARN
```

## Implemented Use Cases

These are the use cases currently implemented in this example script:

| Use Case                                                            | Description                                                                                                              | Notes                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [ImportClearTransportKey](./usecases/import_clear_transport_key.go) | Imports a clear key into AWS Payment Cryptography with key usage of TR-31 K1 (**K**ey **B**lock **P**rotection **K**ey). | **This should be used in non-production testing environments only, and demonstrates the complete workflow involved in a ECDH-based key exchange.** Real-world production workflows will involve the Party U HSM generate (and maybe sign) it's ECC key pair, as well as derive the one-time ECDH key and export the transport master key under a TR-31 key block afterwards. |
| [PINSelect](./usecases/pin_select.go)                               | Simulates a PIN select operation, where a clear PIN and a PAN are processed all the way up to PVV generation.            | -                                                                                                                                                                                                                                                                                                                                                                            |

> ✅ Make sure to have an AWS CLI "default" profile configured in order to use the Makefile example commands as-is. Otherwise, update the commands to provide your custom profile name.

Check the [Makefile](./Makefile) for some ready-to-use examples of each use case.