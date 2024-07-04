// +build !cgo

// Package bls implements a go-wrapper around a library implementing the
// the BLS12-381 curve and signature scheme. This package exposes a public API for
// verifying and aggregating BLS signatures used by Ethereum 2.0.
package bls

import (
	"crypto/rand"
	"time"

	"github.com/karlseguin/ccache"
	kbls "github.com/kilic/bls12-381"
	"github.com/pkg/errors"
	bls12 "github.com/protolambda/bls12-381-util"
	"github.com/prysmaticlabs/prysm/crypto/bls/common"
)

// SecretKeyFromBytes creates a BLS private key from a BigEndian byte slice.
func SecretKeyFromBytes(privKey []byte) (SecretKey, error) {
	return secretKeyFromBytes(privKey)
}

func PublicKeyFromBytes(pubKey []byte) (PublicKey, error) {
	return publicKeyFromBytes(pubKey)
}

// SignatureFromBytesNoValidation creates a BLS signature from a LittleEndian byte slice.
// It does not check validity of the signature, use only when the byte slice has
// already been verified
func SignatureFromBytesNoValidation(sig []byte) (Signature, error) {
	return signatureFromBytes(sig)
}

func SignatureFromBytes(sig []byte) (Signature, error) {
	return signatureFromBytes(sig)
}

// MultipleSignaturesFromBytes creates a slice of BLS signatures from a LittleEndian 2d-byte slice.
func MultipleSignaturesFromBytes(sigs [][]byte) ([]Signature, error) {
	var signatures []Signature
	for _, sig := range sigs {
		newSig, err := signatureFromBytes(sig)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, newSig)
	}
	return signatures, nil
}

// AggregatePublicKeys aggregates the provided raw public keys into a single key.
func AggregatePublicKeys(pubs [][]byte) (PublicKey, error) {
	var publicKeys []*bls12.Pubkey
	for _, pub := range pubs {
		newPubKey := new(bls12.Pubkey)
		pub48 := toBytes48(pub)
		err := newPubKey.Deserialize(&pub48)
		if err != nil {
			return nil, err
		}
		publicKeys = append(publicKeys, newPubKey)
	}
	resultKey, err := bls12.AggregatePubkeys(publicKeys)
	if err != nil {
		return nil, err
	}
	return &publicKey{p: resultKey}, nil
}

// AggregateMultiplePubkeys aggregates the provided decompressed keys into a single key.
func AggregateMultiplePubkeys(pubs []PublicKey) PublicKey {
	var publicKeys []*bls12.Pubkey
	for _, pub := range pubs {
		publicKeys = append(publicKeys, pub.(*publicKey).p)
	}
	resultKey, err := bls12.AggregatePubkeys(publicKeys)
	if err != nil {
		return nil
	}
	return &publicKey{p: resultKey}
}

// AggregateSignatures converts a list of signatures into a single, aggregated sig.
func AggregateSignatures(sigs []common.Signature) common.Signature {
	var sigArray []*bls12.Signature
	for _, sig := range sigs {
		if sig != nil {
			sigArray = append(sigArray, sig.(*signature).s)
		}
	}
	aggregate, err := bls12.Aggregate(sigArray)
	if err != nil {
		return nil
	}
	return &signature{s: aggregate}
}

// AggregateCompressedSignatures converts a list of compressed signatures into a single, aggregated sig.
func AggregateCompressedSignatures(multiSigs [][]byte) (common.Signature, error) {
	var sigArray []*bls12.Signature
	for _, sig := range multiSigs {
		newSig := new(bls12.Signature)
		sig96 := toBytes96(sig)
		err := newSig.Deserialize(&sig96)
		if err != nil {
			return nil, err
		}
		sigArray = append(sigArray, newSig)
	}
	aggregate, err := bls12.Aggregate(sigArray)
	if err != nil {
		return nil, err
	}
	return &signature{s: aggregate}, nil
}

// VerifySignature verifies a single signature. For performance reason, always use VerifyMultipleSignatures if possible.
func VerifySignature(sig []byte, msg [32]byte, pubKey common.PublicKey) (bool, error) {
	newSig, err := signatureFromBytes(sig)
	if err != nil {
		return false, err
	}
	result := newSig.Verify(pubKey, msg[:])
	return result, nil
}

// VerifyMultipleSignatures verifies multiple signatures for distinct messages securely.
func VerifyMultipleSignatures(sigs [][]byte, msgs [][32]byte, pubKeys []common.PublicKey) (bool, error) {
	var sset bls12.SignatureSet
	for i, sig := range sigs {
		currentSignature, err := signatureFromBytes(sig)
		if err != nil {
			return false, err
		}
		currentKey := pubKeys[i].(*publicKey).p
		currentMsg := msgs[i][:]
		sset.Add(currentKey, currentMsg, currentSignature.s)
	}
	result := sset.Verify()
	return result, nil
}

// NewAggregateSignature creates a blank aggregate signature.
func NewAggregateSignature() common.Signature {
	panic("unsupported NewAggregateSignature when !cgo")
}

// RandKey creates a new private key using a random method provided as an io.Reader.
func RandKey() (SecretKey, error) {
	newFr := new(kbls.Fr)
	fr, err := newFr.Rand(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &secretKey{p: (*bls12.SecretKey)(fr)}, nil
}

var pubkeyCache = ccache.New(ccache.Configure())

var privkeyCache = ccache.New(ccache.Configure())

// Signature used in the BLS signature scheme.
type signature struct {
	s *bls12.Signature
}

// PublicKey used in the BLS signature scheme.
type publicKey struct {
	p *bls12.Pubkey
}

// SecretKey used in the BLS signature scheme.
type secretKey struct {
	p *bls12.SecretKey
}

// Sign a message using a secret key - in a beacon/validator client.
func (s *secretKey) Sign(msg []byte) Signature {
	sign := bls12.Sign(s.p, msg)
	return &signature{s: sign}
}

// PublicKey obtains the public key corresponding to the BLS secret key.
func (s *secretKey) PublicKey() PublicKey {
	pk, err := bls12.SkToPk(s.p)
	if err != nil {
		return nil
	}
	return &publicKey{p: pk}
}

// Marshal a secret key into a LittleEndian byte slice.
func (s *secretKey) Marshal() []byte {
	out := s.p.Serialize()
	return out[:]
}

// Marshal a secret key into a LittleEndian byte slice.
func (s *secretKey) copy() SecretKey {
	out := s.p.Serialize()
	newKey := new(bls12.SecretKey)
	err := newKey.Deserialize(&out)
	if err != nil {
		return nil
	}
	return &secretKey{p: newKey}
}

// SignatureFromBytes creates a BLS signature from a LittleEndian byte slice.
func signatureFromBytes(sig []byte) (*signature, error) {
	newSignature := new(bls12.Signature)
	sig96 := toBytes96(sig)
	err := newSignature.Deserialize(&sig96)
	if err != nil {
		return nil, errors.Wrap(err, "could not unmarshal bytes into signature")
	}
	return &signature{s: newSignature}, nil
}

func (s *signature) Verify(pubKey PublicKey, msg []byte) bool {
	return bls12.Verify(pubKey.(*publicKey).p, msg, s.s)
}

// toBytes32 is a convenience method for converting a byte slice to a fix
// sized 32 byte array. This method will truncate the input if it is larger
// than 32 bytes.
func toBytes32(x []byte) [32]byte {
	var y [32]byte
	copy(y[:], x)
	return y
}

// toBytes48 is a convenience method for converting a byte slice to a fix
// sized 48 byte array. This method will truncate the input if it is larger
// than 48 bytes.
func toBytes48(x []byte) [48]byte {
	var y [48]byte
	copy(y[:], x)
	return y
}

// toBytes96 is a convenience method for converting a byte slice to a fix
// sized 96 byte array. This method will truncate the input if it is larger
// than 96 bytes.
func toBytes96(x []byte) [96]byte {
	var y [96]byte
	copy(y[:], x)
	return y
}

// Marshal a signature into a LittleEndian byte slice.
func (s *signature) Marshal() []byte {
	out := s.s.Serialize()
	return out[:]
}

func (s *signature) AggregateVerify(pubKeys []PublicKey, msgs [][32]byte) bool {
	var pubk []*bls12.Pubkey
	for _, oneKey := range pubKeys {
		pubk = append(pubk, oneKey.(*publicKey).p)
	}
	var messages [][]byte
	for _, oneMsg := range msgs {
		messages = append(messages, oneMsg[:])
	}
	return bls12.AggregateVerify(pubk, messages, s.s)
}

func (s *signature) FastAggregateVerify(pubKeys []PublicKey, msg [32]byte) bool {
	var pubk []*bls12.Pubkey
	for _, oneKey := range pubKeys {
		pubk = append(pubk, oneKey.(*publicKey).p)
	}
	return bls12.FastAggregateVerify(pubk, msg[:], s.s)
}
func (s *signature) Eth2FastAggregateVerify(pubKeys []PublicKey, msg [32]byte) bool {
	var pubk []*bls12.Pubkey
	for _, oneKey := range pubKeys {
		pubk = append(pubk, oneKey.(*publicKey).p)
	}
	return bls12.Eth2FastAggregateVerify(pubk, msg[:], s.s)
}

func (s *signature) Copy() Signature {
	out := s.s.Serialize()
	newSignature := new(bls12.Signature)
	err := newSignature.Deserialize(&out)
	if err != nil {
		return nil
	}
	return &signature{s: newSignature}
}

// PublicKeyFromBytes creates a BLS public key from a  LittleEndian byte slice.
func publicKeyFromBytes(pub []byte) (*publicKey, error) {
	cv := pubkeyCache.Get(string(pub))
	if cv != nil && cv.Value() != nil {
		return cv.Value().(*publicKey).Copy().(*publicKey), nil
	}
	b := toBytes48(pub)
	newKey := new(bls12.Pubkey)
	err := newKey.Deserialize(&b)
	if err != nil {
		return nil, errors.Wrap(err, "could not unmarshal bytes into public key")
	}
	pubkey := &publicKey{p: newKey}
	pubkeyCache.Set(string(pub), pubkey.Copy(), 48*time.Hour)
	return pubkey, nil
}

func secretKeyFromBytes(privKey []byte) (SecretKey, error) {
	cv := privkeyCache.Get(string(privKey))
	if cv != nil && cv.Value() != nil {
		return cv.Value().(*secretKey).copy().(*secretKey), nil
	}
	b := toBytes32(privKey)
	newKey := new(bls12.SecretKey)
	err := newKey.Deserialize(&b)
	if err != nil {
		return nil, errors.Wrap(err, "could not unmarshal bytes into secret key")
	}
	secKey := &secretKey{p: newKey}
	privkeyCache.Set(string(privKey), secKey.copy(), 48*time.Hour)
	return secKey, nil
}

// Marshal a public key into a LittleEndian byte slice.
func (p *publicKey) Marshal() []byte {
	out := p.p.Serialize()
	return out[:]
}

// Copy the public key to a new pointer reference.
func (p *publicKey) Copy() PublicKey {
	out := p.p.Serialize()
	newKey := new(bls12.Pubkey)
	err := newKey.Deserialize(&out)
	if err != nil {
		return nil
	}
	return &publicKey{p: newKey}
}

func (p *publicKey) Aggregate(p2 PublicKey) PublicKey {
	var pubk []*bls12.Pubkey
	pubk = append(pubk, p.p)
	pubk = append(pubk, p2.(*publicKey).p)
	pubkey, err := bls12.AggregatePubkeys(pubk)
	if err != nil {
		return nil
	}
	return &publicKey{p: pubkey}
}

func (p *publicKey) IsInfinite() bool {
	panic("not support IsInfinite")
}

func (p *publicKey) Equals(p2 PublicKey) bool {
	panic("not support Equals")
}
