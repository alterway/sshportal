package crypto // import "moul.io/sshportal/pkg/crypto"

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"unicode/utf8"

	gossh "golang.org/x/crypto/ssh"
	"moul.io/sshportal/pkg/dbmodels"
)

func NewSSHKey(keyType string, length uint) (*dbmodels.SSHKey, error) {
	key := dbmodels.SSHKey{
		Type:   keyType,
		Length: length,
	}

	// generate the private key
	var err error
	var pemKey *pem.Block
	var publicKey gossh.PublicKey
	switch keyType {
	case "rsa":
		pemKey, publicKey, err = NewRSAKey(length)
	case "ecdsa":
		pemKey, publicKey, err = NewECDSAKey(length)
	case "ed25519":
		pemKey, publicKey, err = NewEd25519Key()
		key.Length = 256 // Ed25519 keys are always 256 bits
	default:
		return nil, fmt.Errorf("key type not supported: %q, supported types are: rsa, ecdsa, ed25519", key.Type)
	}
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBufferString("")
	if err = pem.Encode(buf, pemKey); err != nil {
		return nil, err
	}
	key.PrivKey = buf.String()

	// generate authorized-key formatted pubkey output
	key.PubKey = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(publicKey)))

	return &key, nil
}

func NewRSAKey(length uint) (*pem.Block, gossh.PublicKey, error) {
	if length < 1024 || length > 16384 {
		return nil, nil, fmt.Errorf("key length not supported: %d, supported values are between 1024 and 16384", length)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, int(length))
	if err != nil {
		return nil, nil, err
	}
	// convert priv key to x509 format
	pemKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	publicKey, err := gossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pemKey, publicKey, err
}

func NewECDSAKey(length uint) (*pem.Block, gossh.PublicKey, error) {
	var curve elliptic.Curve
	switch length {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, nil, fmt.Errorf("key length not supported: %d, supported values are 256, 384, 521", length)
	}
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// convert priv key to x509 format
	marshaledKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	pemKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledKey,
	}
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := gossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pemKey, publicKey, err
}

func NewEd25519Key() (*pem.Block, gossh.PublicKey, error) {
	publicKeyEd25519, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// convert priv key to x509 format
	marshaledKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	pemKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledKey,
	}
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := gossh.NewPublicKey(publicKeyEd25519)
	if err != nil {
		return nil, nil, err
	}
	return pemKey, publicKey, err
}

func ImportRSASSHKey(keyValue string) (*dbmodels.SSHKey, error) {
	key := dbmodels.SSHKey{
		Type: "rsa",
	}

	parsedKey, err := gossh.ParseRawPrivateKey([]byte(keyValue))
	if err != nil {
		return nil, err
	}
	var privateKey *rsa.PrivateKey
	var ok bool
	if privateKey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("key type not supported")
	}
	key.Length = uint(privateKey.PublicKey.N.BitLen())
	// convert priv key to x509 format
	var pemKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	buf := bytes.NewBufferString("")
	if err = pem.Encode(buf, pemKey); err != nil {
		return nil, err
	}
	key.PrivKey = buf.String()

	// generte authorized-key formatted pubkey output
	pub, err := gossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	key.PubKey = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))

	return &key, nil
}

func ImportEd25519SSHKey(keyValue string) (*dbmodels.SSHKey, error) {
	key := dbmodels.SSHKey{
		Type: "ed25519",
	}

	parsedKey, err := gossh.ParseRawPrivateKey([]byte(keyValue))
	if err != nil {
		return nil, err
	}

	// Handle both ed25519.PrivateKey and *ed25519.PrivateKey
	var privateKey ed25519.PrivateKey
	var ok bool

	// Try direct type assertion first
	if privateKey, ok = parsedKey.(ed25519.PrivateKey); !ok {
		// Try pointer type assertion and dereference
		// See golang/go#51974 for more details.
		if privateKeyPtr, ok := parsedKey.(*ed25519.PrivateKey); ok {
			privateKey = *privateKeyPtr
		} else {
			return nil, fmt.Errorf("key type not supported")
		}
	}

	key.Length = 256 // Ed25519 keys are always 256 bits

	// Keep the original key format if it's already PEM encoded
	if strings.Contains(keyValue, "-----BEGIN") {
		key.PrivKey = keyValue
	} else {
		// convert priv key to x509 format
		marshaledKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		var pemKey = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: marshaledKey,
		}
		buf := bytes.NewBufferString("")
		if err = pem.Encode(buf, pemKey); err != nil {
			return nil, err
		}
		key.PrivKey = buf.String()
	}

	// generate authorized-key formatted pubkey output
	publicKey := privateKey.Public().(ed25519.PublicKey)
	pub, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	key.PubKey = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))

	return &key, nil
}

func encrypt(key []byte, byteText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	aesgcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return []byte{}, err
	}

	return aesgcm.Seal(nil, nil, byteText, nil), err
}

func decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	aesgcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return []byte{}, err
	}

	plaintext, err := aesgcm.Open(nil, nil, ciphertext, nil)
	if err != nil {
		return []byte{}, err
	}
	return plaintext, nil
}

// DecryptCFBField DEPRECATED
// Only used to migrate old encrypted DB fields to the new cipher
// This function also return the field without error if found unencrypted
// This behavior is not present in the new DecryptField() function
func DecryptCFBField(aesKey string, field string) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(field)

	// The field is not base64 encoded so it wasn't encrypted.
	// We return the unencrypted field
	if err != nil {
		return field, nil
	}

	// If the ciphertext length  is less than 128 bits, we can't decrypt and
	// that means it wasn't previously encrypted. So we return the plaintext field
	//
	// For example, the field "qwertyi" is considered as a valid base64 string
	// and would pass the previous check
	// Any password > 16 chars which could be considered as a base64 string
	// will not be catched here
	if len(ciphertext) < aes.BlockSize {
		return field, nil
	}

	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return "", err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv) // nolint:staticcheck

	// work in-place if the two arguments are the same
	stream.XORKeyStream(ciphertext, ciphertext)

	// The supposed decrypted field should be a UTF8 string.
	// If not, it means the field was not encrypted.
	// This final check will catch all the others passwords
	// which were not encrypted but mis-identified as base64 strings
	if !utf8.Valid(ciphertext) || len(ciphertext) == 0 {
		return field, nil
	}

	return string(ciphertext), nil
}

func EncryptField(aesKey string, field *string) error {
	if aesKey == "" {
		return nil
	}

	cryptoText, err := encrypt([]byte(aesKey), []byte(*field))
	if err != nil {
		return err
	}

	*field = base64.URLEncoding.EncodeToString(cryptoText)

	return nil
}

func DecryptField(aesKey string, field *string) error {
	if aesKey == "" {
		return nil
	}

	cryptoText, err := base64.URLEncoding.DecodeString(*field)
	if err != nil {
		return err
	}

	plaintext, err := decrypt([]byte(aesKey), cryptoText)
	if err != nil {
		return err
	}

	*field = string(plaintext)

	return nil
}

func EncryptBackup(aesKey string, data []byte) ([]byte, error) {
	if aesKey == "" {
		return []byte{}, fmt.Errorf("encryption backup with no aes key")
	}
	return encrypt([]byte(aesKey), data)
}

func DecryptBackup(aesKey string, data []byte) ([]byte, error) {
	if aesKey == "" {
		return []byte{}, nil
	}
	return decrypt([]byte(aesKey), data)
}
