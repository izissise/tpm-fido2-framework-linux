package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// Run against a simulator, never the real TPM:
//   swtpm socket --tpm2 --flags startup-clear --tpmstate dir=$D --server type=unixio,path=$D/sock --ctrl type=unixio,path=$D/ctrl
//   TPM_FIDO_TEST_TPM=$D/sock go test ./tpm
func TestKeysNeedMasterSecret(t *testing.T) {
	dev := os.Getenv("TPM_FIDO_TEST_TPM")
	if dev == "" {
		t.Skip("TPM_FIDO_TEST_TPM not set")
	}

	if _, err := New(dev, make([]byte, 31)); err == nil {
		t.Fatal("31-byte master secret accepted")
	}
	a, err := New(dev, bytes.Repeat([]byte{1}, 128))
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(dev, bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}

	app := sha256.Sum256([]byte("example.com"))
	digest := sha256.Sum256([]byte("challenge"))
	handle, x, y, err := a.RegisterKey(app[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := a.SignASN1(handle, app[:], digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], sig) {
		t.Fatal("signature does not verify")
	}

	before := lockoutCounter(t, dev)
	if _, err := b.SignASN1(handle, app[:], digest[:]); err == nil {
		t.Fatal("signed with the wrong master secret")
	}
	if after := lockoutCounter(t, dev); after != before {
		t.Fatalf("failed auth hit the DA lockout counter: %d -> %d", before, after)
	}

	ra, _ := a.DeriveCredRandom(handle)
	rb, _ := b.DeriveCredRandom(handle)
	if bytes.Equal(ra, rb) {
		t.Fatal("PRF output does not depend on the master secret")
	}
}

func lockoutCounter(t *testing.T, dev string) uint32 {
	rw, err := tpm2.OpenTPM(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	vals, _, err := tpm2.GetCapability(rw, tpm2.CapabilityTPMProperties, 1, 0x20E) // TPM_PT_LOCKOUT_COUNTER
	if err != nil {
		t.Fatal(err)
	}
	return vals[0].(tpm2.TaggedProperty).Value
}
