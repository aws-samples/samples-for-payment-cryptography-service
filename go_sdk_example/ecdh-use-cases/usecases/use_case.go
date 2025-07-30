// Package usecases implements several example use cases
// for AWS Payment Cryptography's ECDH mechanism.
package usecases

import "context"

// UseCase represents any implementation able to perform actions at AWS Payment
// Cryptography using an ECDH information packet.
type UseCase interface {
	// Execute performs the main use case flow.
	Execute(ctx context.Context, ecdhPacket *ECDHPacket) error
}

// ECDHPacket is a condensed data packet containing relevant ECDH information for the execution of use cases.
type ECDHPacket struct {
	// Secret material resulting of the ECDH operation
	SharedSecret []byte
	// Party U's (operation initiator) CA certificate identifier at AWS Payment Cryptography
	PartyUCAArn string
	// PEM bytes of the certificate containing Party U's ECC public key
	PartyUCertPEM []byte
	// Party V's (AWS Payment Cryptography itself) ECC key pair identifier at AWS Payment Cryptography
	PartyVECCKeyPairArn string
}
