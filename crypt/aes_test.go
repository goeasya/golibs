package crypt_test

import (
	"testing"

	"github.com/goeasya/golibs/crypt"
)

const (
	testKey   = "12345678901234567890123456789012"
	testValue = "hi, test"
)

var encryptData = []byte{136, 169, 94, 203, 251, 163, 123, 88, 185, 40, 251, 232, 184, 57, 64, 79}

func TestAesEncryptCBC(t *testing.T) {
	out, err := crypt.AesEncryptCBC([]byte(testValue), []byte(testKey))
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(out) != len(encryptData) {
		t.Fatalf("except %v, but output: %v", encryptData, out)
	}

	for idx, v := range out {
		if encryptData[idx] != v {
			t.Fatalf("except %v, but output: %v", encryptData, out)
		}
	}
}

func TestAesDecryptCBC(t *testing.T) {
	out, err := crypt.AesDecryptCBC(encryptData, []byte(testKey))
	if err != nil {
		t.Fatal(err.Error())
	}
	if string(out) != testValue {
		t.Fatalf("except: [%s], but output: [%s]", testValue, out)
	}
}
