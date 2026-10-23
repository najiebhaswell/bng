package radius

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
)

// TestAccountingMessageAuthenticator checks an Accounting-Request the way a
// server does: the Request Authenticator is an MD5 over the packet and the
// Message-Authenticator an HMAC over the packet with a zero Authenticator.
func TestAccountingMessageAuthenticator(t *testing.T) {
	secret := []byte("testing123")
	packet := radius.New(radius.CodeAccountingRequest, secret)
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Start)
	rfc2865.UserName_SetString(packet, "user1")
	if err := addMessageAuthenticator(packet, secret); err != nil {
		t.Fatal(err)
	}
	wire, err := packet.Encode()
	if err != nil {
		t.Fatal(err)
	}

	got := rfc2869.MessageAuthenticator_Get(packet)
	zeroed, err := packet.Encode()
	if err != nil {
		t.Fatal(err)
	}
	copy(zeroed[4:20], make([]byte, 16))
	// Blank the Message-Authenticator value in the zeroed copy
	i := bytes.Index(zeroed, got)
	if i < 0 {
		t.Fatal("Message-Authenticator not found in packet")
	}
	copy(zeroed[i:i+16], make([]byte, 16))
	mac := hmac.New(md5.New, secret)
	mac.Write(zeroed)
	if !hmac.Equal(got, mac.Sum(nil)) {
		t.Fatal("Message-Authenticator does not verify")
	}

	if !radius.IsAuthenticRequest(wire, secret) {
		t.Fatal("Request Authenticator does not verify")
	}
}
