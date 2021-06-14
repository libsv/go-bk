package bip32

import (
	"errors"
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DerivePathAndDeriveSeed(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		counter      uint64
		startingPath string
		exp          string
	}{
		"successful run should return no errors": {
			counter:      0,
			startingPath: "",
			exp:          "2147483648/2147483648/2147483648",
		}, "172732732 counter with 0 path": {
			counter:      172732732,
			startingPath: "",
			exp:          "2147483648/2190666831/2147483648",
		}, "max int should return max int with root path": {
			counter:      math.MaxInt32 + 172732732,
			startingPath: "",
			exp:          "2147483648/2727537742/2147483651",
		}, "max int * 2 should return 1 with root path": {
			counter:      (math.MaxInt32 * 10000) + 172732732,
			startingPath: "",
			exp:          "2147488648/2190664331/2147483648",
		}, "max int squared should return 0/0 path": {
			counter:      (math.MaxInt32 * math.MaxInt32) + 172732732,
			startingPath: "",
			exp:          "3221225471/2190666831/2147483649",
		}, "max int squared + 100 should return correct path": {
			counter:      (math.MaxInt32*math.MaxInt32 + (math.MaxInt32 * 100)) + 172732732,
			startingPath: "",
			exp:          "3221225521/2190666806/2147483649",
		}, "max int squared plus two int32 should return correct path": {
			counter:      ((math.MaxInt32 * math.MaxInt32 * 1) + (math.MaxInt32 * 2)) + 172732732,
			startingPath: "",
			exp:          "3221225472/2190666830/2147483651",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.exp, DerivePath(test.counter))
			// assert the path can be converted correctly back to the seed.
			c, _ := DeriveSeed(test.exp)
			assert.Equal(t, test.counter, c)
		})
	}
}

func TestDeriveSeed(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		path string
		err  error
	}{
		"missing path should error": {
			err: errors.New("path must have 3 levels ie 0/0/0"),
		},
		"path too long should error": {
			path: "0/0/0/0",
			err:  errors.New("path must have 3 levels ie 0/0/0"),
		},
		"path too short should error": {
			path: "0/0",
			err:  errors.New("path must have 3 levels ie 0/0/0"),
		},
		"path length 3 should not error": {
			path: "0/0/0",
			err:  nil,
		},
		"path overflow uint32 should error": {
			path: "4294967296/0/0",
			err: &strconv.NumError{
				Func: "ParseUint",
				Num:  "4294967296",
				Err:  errors.New("value out of range"),
			},
		},
		"path less than min uint32 should error": {
			path: "-1/0/0",
			err: &strconv.NumError{
				Func: "ParseUint",
				Num:  "-1",
				Err:  errors.New("invalid syntax"),
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DeriveSeed(test.path)
			assert.Equal(t, test.err, err)
		})
	}
}
