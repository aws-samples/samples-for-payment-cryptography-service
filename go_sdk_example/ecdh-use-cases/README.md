# AWS Payment Cryptography ECDH Use Cases

An example script using the [AWS Go SDK V2](https://github.com/aws/aws-sdk-go-v2) to display several use cases of the ECDH mechanism on AWS Payment  Cryptography service.

## How to use it?

> 🚩 Executions of the script will attempt to clean any data they generated on the APC. To keep any of the results, comment the relevant deferred Cleanup methods on [main.go](./main.go).

To run a clear key import use case, run:

```sh
# Imports an AES-256 clear key as a KBPK
go run . -aws-profile YOUR_PROFILE_NAME_HERE -use-case ImportClearTransportKey -target-key-algorithm AES256 -target-key 0000000000000000000000000000000000000000000000000000000000000000
```

The application is controlled by flags, to learn more about them and their possible values, run:

```sh
go run . -h
```

## Implemented Use Cases

These are the use cases currently implemented in this example script:

| Use Case                                                            | Description                                                                                                   | Notes                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [ImportClearTransportKey](./usecases/import_clear_transport_key.go) | Imports a clear key into APC with key usage of TR-31 K1 (Key Block Protection Key).                           | **This should be used in non-production testing environments only, and demonstrates the complete workflow involved in a ECDH-based key exchange.** Real-world production workflows will involve the Party U HSM generate (and maybe sign) it's ECC key pair, as well as derive the one-time ECDH key and export the master key under a TR-31 key block afterwards. |
| [PINSelect](./usecases/pin_select.go)                               | Simulates a PIN select operation, where a clear PIN and a PAN are processed all the way up to PVV generation. |                                                                                                                                                                                                                                                                                                                                                                    |

Check the [Makefile](./Makefile) for examples on how to invoke each use case.

> ✅ Make sure to have an AWS CLI "default" profile configured in order to use the Makefile example commands as-is. Otherwise, update the commands to provide your custom profile name.