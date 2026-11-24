package v2rayhttp

import (
	"context"
	"net/http"
	"strings"
)

// HWIDContext is ported from the extended fork: it exposes the X-HWID header
// of an incoming HTTP transport request to the connection handler.
func HWIDContext(ctx context.Context, headers http.Header) context.Context {
	for key, values := range headers {
		if strings.ToLower(key) == "x-hwid" {
			if len(values) != 0 {
				return context.WithValue(ctx, "hwid", values[0])
			}
		}
	}
	return ctx
}
