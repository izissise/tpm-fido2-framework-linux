package ctap2

import (
	"context"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/psanford/tpm-fido/memory"
)

func TestSilentAssertionSkipsFingerprint(t *testing.T) {
	signer, err := memory.New()
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(signer, nil, nil) // nil presence: asking for the fingerprint would panic

	app := HashRPID("example.com")
	handle, _, _, err := signer.RegisterKey(app[:])
	if err != nil {
		t.Fatal(err)
	}
	status, resp := h.GetAssertion(context.Background(), &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: make([]byte, 32),
		AllowList:      []PublicKeyCredentialDescriptor{{Type: CredentialTypePublicKey, ID: handle}},
		Extensions:     map[string]interface{}{"hmac-secret": map[int]interface{}{}},
		Options:        map[string]bool{"up": false},
	})
	if status != StatusSuccess {
		t.Fatalf("status %#x", status)
	}
	var r GetAssertionResponse
	if err := cbor.Unmarshal(resp, &r); err != nil {
		t.Fatal(err)
	}
	if flags := r.AuthData[32]; flags&(FlagUserPresent|FlagUserVerified|FlagExtensionData) != 0 {
		t.Fatalf("silent assertion flags %#x, want no UP/UV/ED", flags)
	}
}
