//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var _ ConfigCompat = (*RealityClientConfig)(nil)

type RealityClientConfig struct {
	uClient       *UTLSClientConfig
	publicKey     []byte
	shortID       [8]byte
	mldsa65Verify []byte
}

func NewRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return newRealityClient(ctx, logger, serverAddress, options, false)
}

func newRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return nil, E.New("uTLS is required by reality client")
	}
	if options.Spoof != "" || options.SpoofMethod != "" {
		return nil, E.New("spoof is unsupported in reality")
	}

	uClient, err := newUTLSClient(ctx, logger, serverAddress, options, allowEmptyServerName, nil, false)
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(options.Reality.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "decode public_key")
	}
	if len(publicKey) != 32 {
		return nil, E.New("invalid public_key")
	}
	var shortID [8]byte
	decodedLen, err := hex.Decode(shortID[:], []byte(options.Reality.ShortID))
	if err != nil {
		return nil, E.Cause(err, "decode short_id")
	}
	if decodedLen > 8 {
		return nil, E.New("invalid short_id")
	}

	// Xray post-quantum REALITY: an ML-DSA-65 verify key requires the extra
	// signature in the certificate extension. Empty keeps classic REALITY.
	var mldsa65Verify []byte
	if options.Reality.MLDSA65Verify != "" {
		mldsa65Verify, err = base64.RawURLEncoding.DecodeString(options.Reality.MLDSA65Verify)
		if err != nil {
			return nil, E.Cause(err, "decode mldsa65_verify")
		}
		if len(mldsa65Verify) != mldsa65.PublicKeySize {
			return nil, E.New("invalid mldsa65_verify")
		}
	}
	var config Config = &RealityClientConfig{
		uClient:       uClient.(*UTLSClientConfig),
		publicKey:     publicKey,
		shortID:       shortID,
		mldsa65Verify: mldsa65Verify,
	}
	if options.KernelRx || options.KernelTx {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}

func (e *RealityClientConfig) ServerName() string {
	return e.uClient.ServerName()
}

func (e *RealityClientConfig) SetServerName(serverName string) {
	e.uClient.SetServerName(serverName)
}

func (e *RealityClientConfig) NextProtos() []string {
	return e.uClient.NextProtos()
}

func (e *RealityClientConfig) SetNextProtos(nextProto []string) {
	e.uClient.SetNextProtos(nextProto)
}

func (e *RealityClientConfig) HandshakeTimeout() time.Duration {
	return e.uClient.HandshakeTimeout()
}

func (e *RealityClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	e.uClient.SetHandshakeTimeout(timeout)
}

func (e *RealityClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for reality")
}

func (e *RealityClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, e)
}

func (e *RealityClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	uConfig := e.uClient.config.Clone()
	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}
	verifier := &realityVerifier{
		serverName:    e.uClient.ServerName(),
		rootCAs:       uConfig.RootCAs,
		currentTime:   nowTime,
		mldsa65Verify: e.mldsa65Verify,
	}
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate
	uConn, err := newRealityUConn(conn, uConfig, e.uClient.id)
	if err != nil {
		return nil, err
	}
	verifier.UConn = uConn
	// Xray v26.9.8+ REALITY rejects a ClientHello with no hybrid X25519MLKEM768
	// share; newRealityUConn adds one to fingerprints that predate ML-KEM.
	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}
	err = uConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 2
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(nowTime.Unix()))
	copy(hello.SessionId[8:], e.shortID[:])
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId[:16]: %v\n", hello.SessionId[:16])
	}
	publicKey, err := ecdh.X25519().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, err
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil {
		return nil, E.New("nil KeyShareKeys")
	}
	ecdheKey := keyShareKeys.Ecdhe
	keyShareName := "x25519"
	// Servers derive the auth key from the standalone X25519 share when
	// offered; the X25519 half of the hybrid share is the fallback.
	if ecdheKey == nil {
		ecdheKey = keyShareKeys.MlkemEcdhe
		keyShareName = "x25519mlkem768"
	}
	if ecdheKey == nil {
		return nil, E.New("nil ecdheKey")
	}
	authKey, err := ecdheKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	if authKey == nil {
		return nil, E.New("nil auth_key")
	}
	verifier.authKey = authKey
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, err
	}
	aesBlock, _ := aes.NewCipher(authKey)
	aesGcmCipher, _ := cipher.NewGCM(aesBlock)
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId: %v\n", hello.SessionId)
		fmt.Printf("REALITY uConn.AuthKey: %v\n", authKey)
	}

	err = uConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}

	if debug.Enabled {
		fmt.Printf("REALITY Conn.Verified: %v\n", verifier.verified)
	}

	if !verifier.verified {
		if debug.Enabled {
			fmt.Printf("REALITY verification failed (auth key from %s, standalone X25519 share present: %v, hybrid X25519MLKEM768 share present: %v, fingerprint: %s-%s)\n",
				keyShareName, keyShareKeys.Ecdhe != nil, keyShareKeys.MlkemEcdhe != nil, e.uClient.id.Client, e.uClient.id.Version)
		}
		realityClientFallback(ctx, uConn, e.uClient.ServerName(), e.uClient.id)
		return nil, E.New("reality verification failed")
	}

	return &realityClientConnWrapper{uConn}, nil
}

// newRealityUConn builds the uTLS connection for [id]. REALITY servers from
// Xray v26.9.8 on reject a ClientHello that carries no X25519MLKEM768 key
// share, so a fingerprint that predates ML-KEM gets one before its spec is
// applied. The configured fingerprint is kept: only the curve list and the key
// share extension gain the group, everything else is the fingerprint's own.
func newRealityUConn(conn net.Conn, config *utls.Config, id utls.ClientHelloID) (*utls.UConn, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		// HelloRandomized builds its spec per connection, HelloCustom and
		// HelloGolang have none. REALITY cannot add a key share to any of them,
		// so fall back to Chrome, the modern preset every REALITY server
		// accepts.
		return utls.UClient(conn, config, utls.HelloChrome_Auto), nil
	}
	changed, usable := ensureMLKEMKeyShare(&spec)
	if !usable {
		// TLS 1.2-only presets (360, Android 11) have no key share extension;
		// REALITY is TLS 1.3 only, so their spec can never carry the handshake.
		return utls.UClient(conn, config, utls.HelloChrome_Auto), nil
	}
	if !changed {
		return utls.UClient(conn, config, id), nil
	}
	// ApplyPreset needs HelloCustom: the spec is what goes on the wire, and the
	// configured id no longer describes it.
	uConn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uConn.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	return uConn, nil
}

// ensureMLKEMKeyShare puts the hybrid X25519MLKEM768 group and key share into
// [spec], first, the order Chrome uses. It reports whether the spec changed and
// whether the spec can carry a TLS 1.3 REALITY handshake at all.
func ensureMLKEMKeyShare(spec *utls.ClientHelloSpec) (changed, usable bool) {
	var curves *utls.SupportedCurvesExtension
	var keyShares *utls.KeyShareExtension
	offersTLS13 := spec.TLSVersMax >= utls.VersionTLS13
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves = ext
		case *utls.KeyShareExtension:
			keyShares = ext
		case *utls.SupportedVersionsExtension:
			for _, version := range ext.Versions {
				if version == utls.VersionTLS13 {
					offersTLS13 = true
				}
			}
		}
	}
	if keyShares == nil || !offersTLS13 {
		return false, false
	}
	if curves != nil {
		hasCurve := false
		for _, curveID := range curves.Curves {
			if curveID == utls.X25519MLKEM768 {
				hasCurve = true
				break
			}
		}
		if !hasCurve {
			curves.Curves = append([]utls.CurveID{utls.X25519MLKEM768}, curves.Curves...)
			changed = true
		}
	}
	for _, share := range keyShares.KeyShares {
		if share.Group == utls.X25519MLKEM768 {
			return changed, true
		}
	}
	keyShares.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}}, keyShares.KeyShares...)
	return true, true
}

func realityClientFallback(ctx context.Context, uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
		},
	}
	serverAddress := M.ParseSocksaddrHostPort(serverName, 0)
	host := serverAddress.AddrString()
	if serverAddress.IsIPv6() {
		host = "[" + host + "]"
	}
	request, err := http.NewRequestWithContext(ctx, "GET", "https://"+host, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mRand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

func (e *RealityClientConfig) Clone() Config {
	return &RealityClientConfig{
		e.uClient.Clone().(*UTLSClientConfig),
		e.publicKey,
		e.shortID,
		e.mldsa65Verify,
	}
}

type realityVerifier struct {
	*utls.UConn
	serverName    string
	rootCAs       *x509.CertPool
	currentTime   time.Time
	authKey       []byte
	mldsa65Verify []byte
	verified      bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeFor[utls.Conn]().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Add(unsafe.Pointer(c.Conn), p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			if len(c.mldsa65Verify) == 0 {
				c.verified = true
				return nil
			}
			// Xray post-quantum REALITY: HMAC(pub || ClientHello || ServerHello)
			// verified against the ML-DSA-65 signature in the first extension.
			if len(c.HandshakeState.Hello.Raw) > 0 &&
				len(c.HandshakeState.ServerHello.Raw) > 0 &&
				len(certs[0].Extensions) > 0 {
				h.Write(c.HandshakeState.Hello.Raw)
				h.Write(c.HandshakeState.ServerHello.Raw)
				if verifyKey, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(c.mldsa65Verify); err == nil {
					if publicKey, isMLDSA := verifyKey.(*mldsa65.PublicKey); isMLDSA &&
						mldsa65.Verify(publicKey, h.Sum(nil), nil, certs[0].Extensions[0].Value) {
						c.verified = true
						return nil
					}
				}
			}
		}
	}
	opts := x509.VerifyOptions{
		Roots:         c.rootCAs,
		CurrentTime:   c.currentTime,
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type realityClientConnWrapper struct {
	*utls.UConn
}

func (c *realityClientConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *realityClientConnWrapper) Upstream() any {
	return c.UConn
}

// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
// We fixed it by calling Close() directly.
func (c *realityClientConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c *realityClientConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *realityClientConnWrapper) WriterReplaceable() bool {
	return false
}
