package crypto // import "github.com/alterway/sshportal/pkg/crypto"

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptField(t *testing.T) {
	aesKey := "aeskeytestaeskeytestaeskeytest12"
	field := "MyBeautifulTestPassword"

	if err := EncryptField(aesKey, &field); err != nil {
		t.Errorf("Encryption failed : %v", err)
	}

	if field == "MyBeautifulTestPassword" {
		t.Errorf("Input and output should not be the same")
	}

	field = "MyBeautifulTestPassword"
	err := EncryptField("", &field)
	if field != "MyBeautifulTestPassword" || err != nil {
		t.Errorf("No encryption should occur if AES key is empty")
	}
}

func TestDecryptField(t *testing.T) {
	aesKey := "aeskeytestaeskeytestaeskeytest12"
	field := "MyBeautifulTestPassword"

	if err := EncryptField(aesKey, &field); err != nil {
		t.Errorf("Encryption failed : %v", err)
	}

	encryptedField := field
	err := DecryptField(aesKey, &encryptedField)
	if encryptedField != "MyBeautifulTestPassword" || err != nil {
		t.Errorf("Decryption failed : %v", err)
	}

	base64Field := base64.URLEncoding.EncodeToString([]byte(field))
	if err := DecryptField(aesKey, &base64Field); err == nil {
		t.Errorf("Non-encrypted field must not be decrypted without error : %s", base64Field)
	}

	encryptedField = field
	err = DecryptField(strings.Replace(aesKey, "a", "b", -1), &encryptedField)
	if encryptedField == "MyBeautifulTestPassword" || err == nil {
		t.Errorf("Bad AES should not decrypt the field : %v", err)
	}

	encryptedField = field
	err = DecryptField("", &field)
	if encryptedField != field || err != nil {
		t.Errorf("No decryption should occur if AES key is empty")
	}
}

func TestDecryptCFBField(t *testing.T) {
	aesKey := "aeskeytestaeskeytestaeskeytest12"
	unencryptedField := "MyBeautifulTestPassword"
	csbEncryptedField := "9wZS90A-RChGRr_LNRt9OFKOBBNpJPQszCxb6_WVD2CD7tiNzFPH"

	decryptedField, err := DecryptCFBField(aesKey, csbEncryptedField)
	if err != nil {
		t.Errorf("Can't decrypt a CFB encrypted field : %v", err)
	}
	if decryptedField != unencryptedField {
		t.Errorf("AES-CFB decryption was not correct : %s != %s", decryptedField, unencryptedField)
	}
}
