package bip32

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DerivePath given a seed will generate a hardened BIP32 path 3 layers deep.
//
// This is achieved by the following process:
// We split the seed bits into 3 sections: (b63-b32|b32-b1|b1-b0)
// Each section is then added onto 2^31 and concatenated together which will give us the final path.
func DerivePath(seed uint64) string {
	path := fmt.Sprintf("%d/", seed>>32|1<<31)
	path += fmt.Sprintf("%d/", ((seed<<32)>>34)|1<<31)
	path += fmt.Sprintf("%d", (seed&3)|1<<31)
	return path
}

// DeriveSeed when given a derivation path of format 0/0/0 will return the seed used to generate
// the path.
func DeriveSeed(path string) (uint64, error) {
	ss := strings.Split(path, "/")
	if len(ss) != 3 {
		return 0, errors.New("path must have 3 levels ie 0/0/0")
	}
	d1, err := strconv.ParseUint(ss[0], 10, 32)
	if err != nil {
		return 0, err
	}
	seed := (d1 - 1<<31) << 32
	d2, err := strconv.ParseUint(ss[1], 10, 32)
	if err != nil {
		return 0, err
	}
	seed += (d2 - (1 << 31)) << 2
	d3, err := strconv.ParseUint(ss[2], 10, 32)
	if err != nil {
		return 0, err
	}
	seed += d3 - (1 << 31)
	return seed, nil
}
