package main

import (
	"encoding/hex"
	"fmt"

	"opaqueauth/internal/keyring"
	"opaqueauth/internal/kms"
)

// buildRing reads the active legacy-key version and retained keys from the
// provider. FileProvider exposes raw names, so the convention is:
//
//	keys["legacy.active.version"] = hex uint32
//	keys["legacy.active.key"]     = hex 32 bytes
//	keys["legacy.v<N>"]           = hex 32 bytes (retained)
//
// MemoryProvider is used in tests; file provisioning is the only supported
// production path.
func buildRing(p kms.Provider) (*keyring.Ring, error) {
	vb, err := p.Get(kms.Name("legacy.active.version"))
	if err != nil {
		return nil, fmt.Errorf("authctl: active key version: %w", err)
	}
	ver, err := parseVersion(vb)
	if err != nil {
		return nil, err
	}
	kb, err := p.Get(kms.Name("legacy.active.key"))
	if err != nil {
		return nil, fmt.Errorf("authctl: active key: %w", err)
	}
	key, err := hex.DecodeString(string(kb))
	if err != nil {
		return nil, fmt.Errorf("authctl: active key is not hex: %w", err)
	}
	return keyring.New(ver, key, nil)
}

func parseVersion(b []byte) (uint32, error) {
	var v uint32
	if _, err := fmt.Sscanf(string(b), "%d", &v); err != nil {
		return 0, fmt.Errorf("authctl: bad key version %q", string(b))
	}
	return v, nil
}
