package v2ray

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// Proves the extended transport types are registered in both constructors.
func TestExtendedTransportRegistration(t *testing.T) {
	ctx := context.Background()
	nopLogger := logger.NOP()
	serverAddr := M.ParseSocksaddr("127.0.0.1:8080")
	for _, testCase := range []struct {
		name    string
		options option.V2RayTransportOptions
	}{
		{name: "xhttp", options: option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeXHTTP,
			XHTTPOptions: option.V2RayXHTTPOptions{
				V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
					Host:          "example.com",
					Path:          "/xhttp",
					XPaddingBytes: option.Range[int]{From: 100, To: 1000},
				},
			},
		}},
		{name: "kcp", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeKCP}},
		{name: "kcp alias", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeKCPAlias}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client, err := NewClientTransportWithLogger(ctx, nopLogger, nil, serverAddr, testCase.options, nil)
			if err != nil {
				t.Fatal(err)
			}
			if client == nil {
				t.Fatal("nil client transport")
			}
			t.Cleanup(func() {
				_ = client.Close()
			})
			server, err := NewServerTransport(ctx, nopLogger, testCase.options, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if server == nil {
				t.Fatal("nil server transport")
			}
			t.Logf("network: %v", server.Network())
		})
	}
}
