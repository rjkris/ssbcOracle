package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	ed1 "ssbcOracle/edwards25519"
	"testing"
)

func DoTestECVRF(t *testing.T, pk, sk []byte, msg []byte, verbose bool) {
	pi, vrfHash, err := Prove(pk, sk, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	ratio := HashRatio(vrfHash)
	t.Logf("vrfHash ratio: %+v", ratio)
	res, err := Verify(pk, pi, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Errorf("VRF failed")
	}

	// when everything get through
	if verbose {
		fmt.Printf("alpha: %s\n", hex.EncodeToString(msg))
		fmt.Printf("x: %s\n", hex.EncodeToString(sk))
		fmt.Printf("P: %s\n", hex.EncodeToString(pk))
		fmt.Printf("pi: %s\n", hex.EncodeToString(pi))
		fmt.Printf("vrf: %s\n", hex.EncodeToString(Hash(pi)))

		r, c, s, err := decodeProof(pi)
		if err != nil {
			t.Fatal(err)
		}
		// u = (g^x)^c * g^s = P^c * g^s
		var u ed1.ProjectiveGroupElement
		P := os2ECP(pk, pk[31]>>7)
		ed1.GeDoubleScalarMultVartime(&u, c, P, s)
		fmt.Printf("r: %s\n", hex.EncodeToString(ecp2OS(r)))
		fmt.Printf("c: %s\n", hex.EncodeToString(c[:]))
		fmt.Printf("s: %s\n", hex.EncodeToString(s[:]))
		fmt.Printf("u: %s\n", hex.EncodeToString(ecp2OSProj(&u)))
	}
}

func TestECVRF(t *testing.T) {
	for i := 10; i > 0; i-- {
		pk, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		var msg [32]byte
		io.ReadFull(rand.Reader, msg[:])
		DoTestECVRF(t, pk, sk, msg[:], false)
	}
}