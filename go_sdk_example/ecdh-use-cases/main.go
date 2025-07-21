package main

import (
	"context"
	"crypto/elliptic"
	"ecdh-use-cases/apcecdh"
	"ecdh-use-cases/enums"
	"ecdh-use-cases/usecases"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"
)

var fAwsProfile string
var fUseCase string
var fTargetKeyAlgorithm string
var fTargetKeyHex string
var fPIN string
var fPAN string

func main() {
	ctx := context.Background()

	flag.StringVar(&fAwsProfile, "aws-profile", "", "aws CLI profile name")
	flag.StringVar(&fUseCase, "use-case", "", fmt.Sprintf("ECDH example use case. One of %v", new(enums.UseCase).Values()))
	flag.StringVar(&fTargetKeyAlgorithm, "target-key-algorithm", "", fmt.Sprintf("Algorithm for the target key. One of %v", new(enums.KeyAlgorithm).Values()))
	flag.StringVar(&fTargetKeyHex, "target-key", "", "Target key bytes in hexadecimal representation. Must match the number of bytes required by algorithm in -target-key-algorithm.")
	flag.StringVar(&fPIN, "pin", "1234", "4-12 digit PIN")
	flag.StringVar(&fPAN, "pan", "1234567890123456", "12-19 digit PAN")
	flag.Parse()

	selectedUseCase := enums.UseCase(fUseCase)
	if !selectedUseCase.Valid() {
		log.Fatalln("Invalid -use-case:", selectedUseCase)
	}

	awsConf, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(fAwsProfile))
	if err != nil {
		log.Fatalln("Failed to create AWS configuration:", err)
	}

	apcECDH := apcecdh.New(awsConf)
	defer apcECDH.Cleanup(context.Background())

	var ecdhPacket *usecases.ECDHPacket
	var useCase usecases.UseCase
	switch selectedUseCase {
	case enums.UseCaseImportClearTransportKey:
		ecdhPacket, err = apcECDH.Setup(ctx, elliptic.P521(), types.DeriveKeyUsageTr31K1KeyBlockProtectionKey)
		if err != nil {
			log.Fatalln("Failed to perform ECDH setup for ImportClearTransportKey:", err)
		}

		targetKeyAlgorithm := enums.KeyAlgorithm(fTargetKeyAlgorithm)
		if !targetKeyAlgorithm.Valid() {
			log.Fatalln("Invalid -target-key-algorithm:", targetKeyAlgorithm)
		}

		targetKey, err := hex.DecodeString(fTargetKeyHex)
		if err != nil {
			log.Fatalln("Invalid -target-key:", err)
		}

		useCase, err = usecases.ImportClearTransportKey(usecases.ImportClearTransportKeyParams{
			AWSConfig:          awsConf,
			TargetKeyAlgorithm: targetKeyAlgorithm,
			TargetKey:          targetKey,
		})
		if err != nil {
			log.Fatalln("Failed to create ImportClearTransportKey use case:", err)
		}

	case enums.UseCasePINSelect:
		ecdhPacket, err = apcECDH.Setup(ctx, elliptic.P256(), types.DeriveKeyUsageTr31P0PinEncryptionKey)
		if err != nil {
			log.Fatalln("Failed to perform ECDH setup for PINSelect:", err)
		}

		useCase, err = usecases.PINSelect(usecases.PINSelectParams{
			AWSConfig: awsConf,
			PIN:       fPIN,
			PAN:       fPAN,
		})
		if err != nil {
			log.Fatalln("Failed to create PINSelect use case:", err)
		}

	default:
		log.Fatalln("Use case not implemented:", selectedUseCase)
	}
	defer useCase.Cleanup(context.Background())

	err = useCase.Execute(ctx, ecdhPacket)
	if err != nil {
		log.Fatalln("Use case execution failed:", err)
	}
}
