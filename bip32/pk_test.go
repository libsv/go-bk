package bip32

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// test addresses generated with https://bip32jp.github.io/english/
func TestPublicKey_DerivationPath(t *testing.T) {
	t.Parallel()
	rootKey, err := NewKeyFromString("tprv8ZgxMBicQKsPcv8v71iiXGDnZ4p6hMc9qiHNdE6p8B79eFrTXVXv35vek8t44ENCbuczHU6co5PqwuAB9YLaDtXuZQrrwacq32BcU7C1TrC")
	if err != nil {
		t.Error(err)
	}
	tests := map[string]struct {
		derivationPath string
		expAddress     string
		err            error
	}{
		"hardened nested path should generate correct address": {
			derivationPath: "0'/0'/3'",
			expAddress:     "mpdFaJf2cAHNfoxKU63o4QXx6NDbzR6E7d",
		}, "hardened root path should generate correct address": {
			derivationPath: "0'",
			expAddress:     "moayMJYrSjfjuiLYxKhhDRUVqDEQWwXzpV",
		}, "standard root path should generate correct address": {
			derivationPath: "0",
			expAddress:     "n2U89ELbUhJWucd9679coQ4W82H4Pme7oX",
		}, "mixed path should generate correct address": {
			derivationPath: "0/1'/2/0'",
			expAddress:     "mkcX3WP4TCLiMU6JXttPnjUJTtjdVsdxBT",
		}, "standard nested path should generate correct address": {
			derivationPath: "0/1/2/5",
			expAddress:     "mjGdCkFd57WJJVzTwFpTRf25XhUDRP3xca",
		}, "invalid derivation path, only letter, should error": {
			derivationPath: "T",
			err:            errors.New("invalid childpath segment T"),
		}, "invalid derivation path, mix of letters and numbers, should error": {
			derivationPath: "0/1/f/4/e",
			err:            errors.New("invalid childpath segment f"),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := rootKey.DeriveChildFromKey(test.derivationPath)
			if test.err != nil {
				assert.Nil(t, key)
				assert.Error(t, err)
				assert.EqualError(t, err, test.err.Error())
				return
			}
			assert.NotNil(t, key)
			assert.NoError(t, err)
			addr, err := key.ToPublicKey()
			assert.NoError(t, err)
			assert.Equal(t, test.expAddress, addr.Address)
		})
	}
}

func TestPrivatekey_getChildInt(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		alias string
		exp   uint32
		err   error
	}{
		"child with '0' should return int": {
			alias: "0",
			exp:   0,
			err:   nil,
		}, "child with '1' should return int": {
			alias: "1",
			exp:   1,
			err:   nil,
		}, "child with hd key '1'' should return hd": {
			alias: "1'",
			exp:   2147483649,
			err:   nil,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r, err := childInt(test.alias)
			if test.err == nil {
				assert.NoError(t, err)
				assert.Equal(t, test.exp, r)
				return
			}
			assert.Empty(t, r)
			assert.Error(t, err)
			assert.Equal(t, test.err, err)
		})
	}
}

func TestPrivatekey_isValidSegment(t *testing.T) {
	tests := map[string]struct {
		segment string
		exp     bool
	}{
		"empty should return invalid": {
			segment: "",
			exp:     false,
		}, "single digit should return valid": {
			segment: "0",
			exp:     true,
		}, "single digit with suffix should return valid": {
			segment: "0'",
			exp:     true,
		}, "large number should return valid": {
			segment: "1234567",
			exp:     true,
		}, "number with unknown char should return invalid": {
			segment: "1234567/",
			exp:     false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.exp, isValidSegment(test.segment))
		})
	}
}
