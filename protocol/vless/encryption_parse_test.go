package vless

import (
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/protocol/vless/encryption"
)

func testEncryptionKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestParseClientEncryption(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(testEncryptionKey())
	for _, testCase := range []struct {
		name       string
		raw        string
		xorMode    uint32
		seconds    uint32
		wantErr    bool
		wantKeyCnt int
	}{
		{name: "native 1rtt", raw: "mlkem768x25519plus.native.1rtt." + key, xorMode: 0, seconds: 0, wantKeyCnt: 1},
		{name: "xorpub 0rtt", raw: "mlkem768x25519plus.xorpub.0rtt." + key, xorMode: 1, seconds: 1, wantKeyCnt: 1},
		{name: "random with padding", raw: "mlkem768x25519plus.random.1rtt.a+b." + key, xorMode: 2, wantKeyCnt: 1},
		{name: "empty", raw: "", wantErr: true},
		{name: "missing segments", raw: "mlkem768x25519plus.native", wantErr: true},
		{name: "bad prefix", raw: "x25519.native.1rtt." + key, wantErr: true},
		{name: "bad mode", raw: "mlkem768x25519plus.foo.1rtt." + key, wantErr: true},
		{name: "bad rtt", raw: "mlkem768x25519plus.native.2rtt." + key, wantErr: true},
		{name: "no key", raw: "mlkem768x25519plus.native.1rtt", wantErr: true},
		{name: "bad key length", raw: "mlkem768x25519plus.native.1rtt." + base64.RawURLEncoding.EncodeToString(make([]byte, 16)), wantErr: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg, err := parseClientEncryption(testCase.raw)
			if testCase.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.xorMode != testCase.xorMode || cfg.seconds != testCase.seconds {
				t.Fatalf("unexpected mode: xorMode=%d seconds=%d", cfg.xorMode, cfg.seconds)
			}
			if len(cfg.keys) != testCase.wantKeyCnt {
				t.Fatalf("unexpected key count: %d", len(cfg.keys))
			}
		})
	}
}

func TestClientEncryptionInit(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(testEncryptionKey())
	cfg, err := parseClientEncryption("mlkem768x25519plus.native.1rtt." + key)
	if err != nil {
		t.Fatal(err)
	}
	instance := &encryption.ClientInstance{}
	err = instance.Init(cfg.keys, cfg.xorMode, cfg.seconds, cfg.padding)
	if err != nil {
		t.Fatal(err)
	}
	if instance.NfsPKeys == nil || len(instance.NfsPKeys) != 1 {
		t.Fatalf("unexpected instance: %+v", instance)
	}
}
