package twofactor

import (
	"crypto"
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strings"

	"rsc.io/qr"
)

const defaultSize = 6

// OATH provides a baseline structure for the two OATH algorithms.
type OATH struct {
	key     []byte
	counter uint64
	size    int
	hash    func() hash.Hash
	algo    crypto.Hash
	issuer  string
}

// Size returns the output size (in characters) of the password.
func (o OATH) Size() int {
	return o.size
}

// Counter returns the OATH token's counter.
func (o OATH) Counter() uint64 {
	return o.counter
}

// SetCounter updates the OATH token's counter to a new value.
func (o OATH) SetCounter(counter uint64) {
	o.counter = counter
}

// Key returns the token's secret key.
func (o OATH) Key() []byte {
	return o.key
}

// Hash returns the token's hash function.
func (o OATH) Hash() func() hash.Hash {
	return o.hash
}

func (o OATH) url(t Type, label string) url.URL {
	secret := base32.StdEncoding.EncodeToString(o.key)
	u := url.URL{}
	v := url.Values{}
	u.Scheme = "otpauth"
	switch t {
	case OATH_HOTP:
		u.Host = "hotp"
	case OATH_TOTP:
		u.Host = "totp"
	}
	u.Path = label
	v.Add("secret", secret)
	if o.Counter() != 0 {
		v.Add("counter", fmt.Sprintf("%d", o.Counter()))
	}
	if o.Size() != defaultSize {
		v.Add("digits", fmt.Sprintf("%d", o.Size()))
	}

	switch {
	case o.algo == crypto.SHA256:
		v.Add("algorithm", "SHA256")
	case o.algo == crypto.SHA512:
		v.Add("algorithm", "SHA512")
	}

	if o.issuer != "" {
		v.Add("issuer", o.issuer)
	} else {
		// assumes colon is the separator
		// TODO add %3A compatibility
		splitLabel := strings.Split(label, ":")
		if len(splitLabel) == 2 {
			// first item is issuer
			o.issuer = splitLabel[0]
			v.Add("issuer", o.issuer)
		}
	}

	u.RawQuery = v.Encode()
	return u

}

var digits = []int64{
	0:  1,
	1:  10,
	2:  100,
	3:  1000,
	4:  10000,
	5:  100000,
	6:  1000000,
	7:  10000000,
	8:  100000000,
	9:  1000000000,
	10: 10000000000,
}

// OTP The top-level type should provide a counter; for example, HOTP
// will provide the counter directly while TOTP will provide the
// time-stepped counter.
func (o OATH) OTP(counter uint64) string {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)

	var mod int64 = 1
	if len(digits) > o.size {
		for i := 1; i <= o.size; i++ {
			mod *= 10
		}
	} else {
		mod = digits[o.size]
	}

	h := hmac.New(o.hash, o.key)
	h.Write(ctr[:])
	dt := truncate(h.Sum(nil)) % mod
	fmtStr := fmt.Sprintf("%%0%dd", o.size)
	return fmt.Sprintf(fmtStr, dt)
}

// truncate contains the DT function from the RFC; this is used to
// deterministically select a sequence of 4 bytes from the HMAC
// counter hash.
func truncate(in []byte) int64 {
	offset := int(in[len(in)-1] & 0xF)
	p := in[offset : offset+4]
	var binCode int32
	binCode = int32((p[0] & 0x7f)) << 24
	binCode += int32((p[1] & 0xff)) << 16
	binCode += int32((p[2] & 0xff)) << 8
	binCode += int32((p[3] & 0xff))
	return int64(binCode) & 0x7FFFFFFF
}

// QR generates a byte slice containing the a QR code encoded as a
// PNG with level Q error correction.
func (o OATH) qr(url string) ([]byte, error) {
	code, err := qr.Encode(url, qr.Q)
	if err != nil {
		return nil, err
	}
	return code.PNG(), nil
}
