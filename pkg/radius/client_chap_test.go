package radius

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// CHAP credentials must go out as CHAP-Password (identifier + response) and
// CHAP-Challenge, without a User-Password.
func TestAuthenticateCHAPAttributes(t *testing.T) {
	const secret = "testing123"
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan *radius.Packet, 1)
	server := &radius.PacketServer{
		SecretSource: radius.StaticSecretSource([]byte(secret)),
		Handler: radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
			received <- r.Packet
			w.Write(r.Response(radius.CodeAccessAccept))
		}),
		InsecureSkipVerify: true,
	}
	go server.Serve(conn)
	defer server.Shutdown(context.Background())

	_, portStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)
	client, err := NewClient(ClientConfig{
		Servers: []ServerConfig{{Host: "127.0.0.1", Port: port, Secret: secret}},
		NASID:   "test",
		Timeout: time.Second,
		Retries: 1,
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	challenge := bytes.Repeat([]byte{0xAB}, 16)
	response := bytes.Repeat([]byte{0xCD}, 16)
	resp, err := client.Authenticate(context.Background(), &AuthRequest{
		Username:      "user",
		CHAPID:        7,
		CHAPChallenge: challenge,
		CHAPResponse:  response,
	})
	if err != nil || !resp.Accepted {
		t.Fatalf("Authenticate = %+v, %v; want accepted", resp, err)
	}

	pkt := <-received
	if got, want := rfc2865.CHAPPassword_Get(pkt), append([]byte{7}, response...); !bytes.Equal(got, want) {
		t.Errorf("CHAP-Password = %x, want %x", got, want)
	}
	if got := rfc2865.CHAPChallenge_Get(pkt); !bytes.Equal(got, challenge) {
		t.Errorf("CHAP-Challenge = %x, want %x", got, challenge)
	}
	if _, err := rfc2865.UserPassword_Lookup(pkt); err == nil {
		t.Error("User-Password present in a CHAP request")
	}
}
