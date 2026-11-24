package option_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// A syntactically valid 32-byte (X25519) key for the extended VLESS encryption.
func testEncryptionKey() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

func testEncryptionString() string {
	return "mlkem768x25519plus.native.1rtt." + testEncryptionKey()
}

func TestVLESSOutboundEncryptionAndXHTTP(t *testing.T) {
	content := `{
		"server": "example.com",
		"server_port": 443,
		"uuid": "3179dce2-2ff9-413c-85b4-c1d53ed41668",
		"encryption": "` + testEncryptionString() + `",
		"transport": {
			"type": "xhttp",
			"mode": "auto",
			"host": "example.com",
			"path": "/xhttp",
			"x_padding_bytes": "100-1000"
		}
	}`
	var options option.VLESSOutboundOptions
	err := json.Unmarshal([]byte(content), &options)
	if err != nil {
		t.Fatal(E.Cause(err, "unmarshal vless outbound"))
	}
	if options.Encryption != testEncryptionString() {
		t.Fatalf("unexpected encryption: %q", options.Encryption)
	}
	if options.Transport == nil || options.Transport.Type != "xhttp" {
		t.Fatalf("unexpected transport: %+v", options.Transport)
	}
	xhttpOptions := options.Transport.XHTTPOptions
	if xhttpOptions.Mode != "auto" {
		t.Fatalf("unexpected xhttp mode: %q", xhttpOptions.Mode)
	}
	if xhttpOptions.Host != "example.com" || xhttpOptions.Path != "/xhttp" {
		t.Fatalf("unexpected xhttp host/path: %q %q", xhttpOptions.Host, xhttpOptions.Path)
	}
	if xhttpOptions.GetNormalizedPath() != "/xhttp/" {
		t.Fatalf("unexpected normalized path: %q", xhttpOptions.GetNormalizedPath())
	}
	if xhttpOptions.XPaddingBytes.From != 100 || xhttpOptions.XPaddingBytes.To != 1000 {
		t.Fatalf("unexpected x_padding_bytes: %+v", xhttpOptions.XPaddingBytes)
	}
	if xhttpOptions.Xmux == nil || xhttpOptions.Xmux.MaxConnections.From != 3 {
		t.Fatalf("unexpected default xmux: %+v", xhttpOptions.Xmux)
	}
	if xhttpOptions.XPaddingPlacement != "queryInHeader" || xhttpOptions.UplinkHTTPMethod != "POST" {
		t.Fatalf("unexpected xhttp defaults: %q %q", xhttpOptions.XPaddingPlacement, xhttpOptions.UplinkHTTPMethod)
	}

	// roundtrip
	encoded, err := json.Marshal(options)
	if err != nil {
		t.Fatal(E.Cause(err, "marshal vless outbound"))
	}
	var roundtrip option.VLESSOutboundOptions
	err = json.Unmarshal(encoded, &roundtrip)
	if err != nil {
		t.Fatal(E.Cause(err, "roundtrip unmarshal"))
	}
	if roundtrip.Transport.Type != "xhttp" || roundtrip.Encryption != options.Encryption {
		t.Fatalf("lost options in roundtrip: %+v", roundtrip)
	}
}

func TestVLESSInboundDecryption(t *testing.T) {
	content := `{
		"users": [{"uuid": "3179dce2-2ff9-413c-85b4-c1d53ed41668"}],
		"decryption": "mlkem768x25519plus.native.1rtt.` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"
	}`
	var options option.VLESSInboundOptions
	err := json.Unmarshal([]byte(content), &options)
	if err != nil {
		t.Fatal(E.Cause(err, "unmarshal vless inbound"))
	}
	if options.Decryption == "" {
		t.Fatal("decryption not parsed")
	}
}

func TestV2RayKCPTransport(t *testing.T) {
	var options option.V2RayTransportOptions
	err := json.Unmarshal([]byte(`{"type":"mkcp","mtu":1400,"header_type":"srtp","congestion":true}`), &options)
	if err != nil {
		t.Fatal(E.Cause(err, "unmarshal mkcp"))
	}
	if options.Type != "mkcp" {
		t.Fatalf("unexpected type: %q", options.Type)
	}
	if options.KCPOptions.GetMTU() != 1400 || options.KCPOptions.GetHeaderType() != "srtp" || !options.KCPOptions.Congestion {
		t.Fatalf("unexpected kcp options: %+v", options.KCPOptions)
	}

	var alias option.V2RayTransportOptions
	err = json.Unmarshal([]byte(`{"type":"kcp"}`), &alias)
	if err != nil {
		t.Fatal(E.Cause(err, "unmarshal kcp alias"))
	}
	if alias.KCPOptions.GetMTU() != 1350 || alias.KCPOptions.GetHeaderType() != "none" {
		t.Fatalf("unexpected kcp defaults: %+v", alias.KCPOptions)
	}
}

func TestV2RayXHTTPRequiresPadding(t *testing.T) {
	var options option.V2RayTransportOptions
	err := json.Unmarshal([]byte(`{"type":"xhttp"}`), &options)
	if err == nil {
		t.Fatal("expected x_padding_bytes validation error, as in the reference implementation")
	}
}
