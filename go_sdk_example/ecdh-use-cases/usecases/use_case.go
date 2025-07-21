// Package usecases implements several example usecases
// for AWS Payment Cryptography's ECDH mechanism.
package usecases

import "context"

type UseCase interface {
	Execute(ctx context.Context, ecdhPacket *ECDHPacket) error
	Cleanup(ctx context.Context)
}

type ECDHPacket struct {
	SharedSecret        []byte
	PartyUCAArn         string
	PartyUCertPEM       []byte
	PartyVECCKeyPairArn string
}
