package licence

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"time"

	"github.com/hashicorp/go-uuid"
)

type Licence struct {
	UUID       string
	ValidFrom  time.Time
	ValidUntil time.Time
	Count      int64 // Zero = unlimited
	Signature  []byte
}

func New(key *rsa.PrivateKey, from, until time.Time, count int64) (*Licence, error) {
	l := Licence{
		ValidFrom:  from,
		ValidUntil: until,
		Count:      count,
	}
	u, err := uuid.GenerateUUID()
	if err != nil {
		return &l, err
	}
	l.UUID = u
	l.Sign(key)
	return &l, nil
}

func Load(s string) (*Licence, error) {
	lb, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var l Licence
	buf := bytes.NewBuffer(lb)
	dec := gob.NewDecoder(buf)
	err = dec.Decode(l)
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func (l *Licence) String() (string, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(*l)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func (l *Licence) Valid(pubkey *rsa.PublicKey) (bool, error) {
	h, err := l.hash()
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, h[:], l.Signature)
	if err != nil {
		return false, err
	}
	if time.Now().UTC().After(l.ValidUntil) || time.Now().UTC().Before(l.ValidFrom) {
		return false, errors.New("outside of licence valid times")
	}
	return true, nil
}

func (l *Licence) Sign(key *rsa.PrivateKey) error {
	h, err := l.hash()
	if err != nil {
		return err
	}
	rnd := rand.Reader
	l.Signature, err = rsa.SignPKCS1v15(rnd, key, crypto.SHA256, h[:])
	if err != nil {
		return err
	}
	return nil
}

func (l *Licence) hash() ([32]byte, error) {
	nl := Licence{
		UUID:       l.UUID,
		ValidFrom:  l.ValidFrom,
		ValidUntil: l.ValidUntil,
		Count:      l.Count,
		Signature:  []byte{},
	}
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(nl)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(buf.Bytes()), nil
}
