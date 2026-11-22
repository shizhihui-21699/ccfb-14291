package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bytemare/opaque"

	"opaqueauth/client"
	"opaqueauth/internal/keyring"
	"opaqueauth/internal/keys"
	"opaqueauth/internal/kms"
	"opaqueauth/internal/secure"
	"opaqueauth/internal/suite"
	"opaqueauth/internal/wire"
)

func loadKeys(p kms.Provider) (*keys.Keys, error) { return keys.Load(p) }

// recoverViaAPI walks the recovery endpoints with the real client SDK's crypto.
func recoverViaAPI(t *testing.T, e *env, id, token, newPW string) error {
	t.Helper()
	conf := suite.Configuration()
	opq, err := conf.Client()
	if err != nil {
		return err
	}
	regReq, err := opq.RegistrationInit([]byte(newPW))
	if err != nil {
		return err
	}
	start := wire.RecoverRedeemStartResponse{}
	if err := postJSON(e.srv.URL+"/v1/recover/redeem/start", wire.RecoverRedeemStartRequest{
		Token: token, RegistrationRequest: regReq.Serialize(),
	}, &start); err != nil {
		return err
	}
	deser, _ := conf.Deserializer()
	resp, err := deser.RegistrationResponse(start.RegistrationResponse)
	if err != nil {
		return err
	}
	opts := &opaque.ClientOptions{
		KSFSalt:       start.KSFSalt,
		KSFParameters: cheap.Params(),
		KSFLength:     cheap.Length,
	}
	rec, _, err := opq.RegistrationFinalize(resp, nil, []byte(suite.ServerIdentity), opts)
	if err != nil {
		return err
	}
	fin := wire.RecoverRedeemFinishResponse{}
	if err := postJSON(e.srv.URL+"/v1/recover/redeem/finish", wire.RecoverRedeemFinishRequest{
		Token: token, Ceremony: start.Ceremony, RegistrationRecord: rec.Serialize(), KSF: start.KSF,
	}, &fin); err != nil {
		return err
	}
	return nil
}

func postJSON(url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var eb wire.ErrorBody
		_ = json.NewDecoder(resp.Body).Decode(&eb)
		return &client.APIError{Status: resp.StatusCode, Code: eb.Code}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

var _ = secure.B64

// mustRing builds a version-1 keyring from loaded keys.
func mustRing(k *keys.Keys) *keyring.Ring {
	r, err := keyring.New(1, k.LegacyVerifier, nil)
	if err != nil {
		panic(err)
	}
	return r
}
