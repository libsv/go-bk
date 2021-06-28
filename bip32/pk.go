package bip32

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/libsv/go-bk/base58"
	"github.com/libsv/go-bk/bec"
	"github.com/libsv/go-bk/chaincfg"
	"github.com/libsv/go-bk/crypto"
)

var (
	reNumericPlusTick = regexp.MustCompile(`^[0-9]+'{0,1}$`)
)

// PublicKey defines a single public key and public address.
type PublicKey struct {
	PublicKey []byte
	Address   string
}

// ToAddress will return the publicKey bytes for the current extendedkey as well as the address.
// An appropriate mainnet or testnet address is determined by the ExtendedKey settings.
//
// If you are using a Zeroed ExtendedKey, use the ToAddressWithNet method.
func (k *ExtendedKey) ToAddress() (*PublicKey, error) {
	return k.ToAddressWithNet(k.IsForNet(&chaincfg.MainNet))
}

// ToAddressWithNet will return the publicKey bytes for the current extendedkey as well as the address.
// This takes a mainnet param that if true will return a mainnet address (prefixed with 1), otherwise
// a testnet address is returned.
//
// This method should only be used if you are dealing with a Zeroed ExtendedKey as it
// cannot determine the network to use. Instead for most instances use ToAddress.
func (k *ExtendedKey) ToAddressWithNet(mainnet bool) (*PublicKey, error) {
	var pubKeyBytes []byte
	if k.key == nil { // can be nil if this is a Zeroed ExtendedKey.
		pubKeyBytes = k.pubKeyBytes()
	} else {
		pub, err := k.ECPubKey()
		if err != nil {
			return nil, fmt.Errorf("failed to convert key to public key %w", err)
		}
		pubKeyBytes = pub.SerialiseCompressed()
		publicKey, err := bec.ParsePubKey(pubKeyBytes, bec.S256())
		if err != nil {
			return nil, err
		}
		pubKeyBytes = publicKey.SerialiseCompressed()
	}
	hash := crypto.Hash160(pubKeyBytes)
	bb := make([]byte, 1)
	if !mainnet {
		bb[0] = 111
	}
	// nolint: makezero // this is required
	bb = append(bb, hash...)
	addr := base58EncodeMissingChecksum(bb)

	size := len(addr)
	if size < 26 || size > 34 {
		return nil, errors.New("incorrect bitcoin address size")
	}
	return &PublicKey{
		PublicKey: pubKeyBytes,
		Address:   addr,
	}, nil
}

// DeriveChildFromKey will return a private key derived from the root startingKey and located at the
// derivationPath.
// Child keys must be ints or hardened keys followed by '.
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func (k *ExtendedKey) DeriveChildFromKey(derivationPath string) (*ExtendedKey, error) {
	if derivationPath == "" {
		return k, nil
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
		k, err = k.Child(childInt)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child from key %w", err)
		}
	}
	return k, nil
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
