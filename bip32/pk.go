package bip32

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/libsv/go-bk/base58"
	"github.com/libsv/go-bk/bec"
	"github.com/libsv/go-bk/crypto"
)

var (
	reNumericPlusTick = regexp.MustCompile(`^[0-9]+'{0,1}$`)
)

// PublicKey defines a single public key and public address.
type PubKey struct {
	PublicKey []byte
	Address   string
}

// PublicKey will take a private key and derive the public key, returning the address string and bytes.
// mainnet will determine if this is a main or testnet address and return the correct prefix accordingly.
func PublicKey(privateKey *ExtendedKey, mainnet bool) (*PubKey, error) {
	pub, err := privateKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to convert key to public key %w", err)
	}
	k := pub.SerialiseCompressed()
	publicKey, err := bec.ParsePubKey(k, bec.S256())
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key %w", err)
	}
	hash := crypto.Hash160(publicKey.SerialiseCompressed())
	bb := make([]byte, 1)
	if !mainnet {
		bb[0] = 111
	}
	bb = append(bb, hash...)
	addr := base58EncodeMissingChecksum(bb)

	size := len(addr)
	if size < 26 || size > 34 {
		return nil, errors.New("incorrect bitcoin address size")
	}
	return &PubKey{
		PublicKey: k,
		Address:   addr,
	}, nil
}

// DeriveChildFromKey will return a private key derived from the root startingKey and located at the
// derivationPath.
// Child keys must be ints or hardened keys followed by '.
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func DeriveChildFromKey(startingKey *ExtendedKey, derivationPath string) (*ExtendedKey, error) {
	if derivationPath == "" {
		return startingKey, nil
	}
	children := strings.Split(derivationPath, "/")
	for _, child := range children {
		if !isValidSegment(child) {
			return nil, fmt.Errorf("invalid childpath segment %s", child)
		}
		childInt, err := childInt(child)
		if err != nil {
			return nil, err
		}
		startingKey, err = startingKey.Child(childInt)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child from key %w", err)
		}
	}
	return startingKey, nil
}

func isValidSegment(child string) bool {
	return reNumericPlusTick.MatchString(child)
}

func childInt(child string) (uint32, error) {
	var suffix uint32
	if strings.HasSuffix(child, "'") {
		child = strings.TrimRight(child, "'")
		suffix = 2147483648 // 2^32
	}
	t, err := strconv.Atoi(child)
	if err != nil {
		return 0, errors.New("child key is not an int")
	}

	return uint32(t) + suffix, nil
}

// base58EncodeMissingChecksum appends a checksum to a byte sequence
// then encodes into base58 encoding.
func base58EncodeMissingChecksum(input []byte) string {
	b := make([]byte, 0, len(input)+4)
	b = append(b, input[:]...)
	cksum := checksum(b)
	b = append(b, cksum[:]...)
	return base58.Encode(b)
}

func checksum(input []byte) (cksum [4]byte) {
	h := crypto.Sha256d(input)
	copy(cksum[:], h[:4])
	return
}
