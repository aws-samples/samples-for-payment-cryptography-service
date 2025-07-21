// Package usecases implements several example use cases
// for AWS Payment Cryptography's ECDH mechanism.
package usecases

import "context"

// UseCase represents any implementation able to perform action at APC using an ECDH information packet.
type UseCase interface {
	// Execute performs the main use case flow.
	Execute(ctx context.Context, ecdhPacket *ECDHPacket) error
	// Cleanup performs any needed post execution cleanup, e.g. deleting generated keys
	// from APC. This function should be deferred as soon as possible in the majority of
	// cases.
	Cleanup(ctx context.Context)
}

type ECDHPacket struct {
	SharedSecret        []byte
	PartyUCAArn         string
	PartyUCertPEM       []byte
	PartyVECCKeyPairArn string
}
