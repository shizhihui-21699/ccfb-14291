package auth_test

import (
	"github.com/bytemare/opaque"
	"opaqueauth/internal/suite"
)

func provisionServerKeyMaterial(t interface{ Fatalf(string, ...any) }) ([]byte, error) {
	conf := suite.Configuration()
	seed := conf.GenerateOPRFSeed()
	sk, pk := conf.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		PrivateKey: sk, PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: seed, Identity: []byte(suite.ServerIdentity),
	}
	return skm.Encode(), nil
}
