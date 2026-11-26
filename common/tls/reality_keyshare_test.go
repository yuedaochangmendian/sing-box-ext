//go:build with_utls

package tls

import (
	"net"
	"testing"

	utls "github.com/metacubex/utls"
)

func TestEnsureMLKEMKeyShareAddsTheHybridShare(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_Auto)
	if err != nil {
		t.Fatal(err)
	}
	_, usable := ensureMLKEMKeyShare(&spec)
	// Newer uTLS builds already carry X25519MLKEM768 in the Firefox spec, so
	// `changed` may be false; what matters is that the spec can carry the
	// hybrid share (and that the generated ClientHello does so, checked below).
	if !usable {
		t.Fatal("the firefox spec cannot carry a TLS 1.3 hybrid key share")
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	uConn := utls.UClient(client, &utls.Config{ServerName: "example.com"}, utls.HelloCustom)
	if err := uConn.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	keys := uConn.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.Ecdhe == nil {
		t.Fatalf("standalone X25519 share missing: %+v", keys)
	}
	if keys.MlkemEcdhe == nil {
		t.Fatal("the hybrid X25519MLKEM768 share was not generated")
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if len(uConn.HandshakeState.Hello.Raw) == 0 {
		t.Fatal("the ClientHello was not marshaled")
	}
}

func TestSupportedFingerprintsOfferTheHybridShare(t *testing.T) {
	for _, name := range []string{
		"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
		"random", "randomized",
	} {
		t.Run(name, func(t *testing.T) {
			id, err := uTLSClientHelloID(name)
			if err != nil {
				t.Fatal(err)
			}
			client, server := net.Pipe()
			uConn, err := newRealityUConn(client, &utls.Config{ServerName: "example.com"}, id)
			if err != nil {
				client.Close()
				server.Close()
				t.Fatal(err)
			}
			if err := uConn.BuildHandshakeState(); err != nil {
				client.Close()
				server.Close()
				t.Fatal(err)
			}
			keys := uConn.HandshakeState.State13.KeyShareKeys
			client.Close()
			server.Close()
			if keys == nil || keys.MlkemEcdhe == nil {
				t.Fatalf("no hybrid X25519MLKEM768 share: %+v", keys)
			}
		})
	}
}

func TestEnsureMLKEMKeyShareKeepsChromeIntact(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	if changed, usable := ensureMLKEMKeyShare(&spec); changed || !usable {
		t.Fatalf("chrome already offers the hybrid key share: changed=%v usable=%v", changed, usable)
	}
}
