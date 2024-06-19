package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strconv"

	"golang.org/x/crypto/argon2"
)

// Hash returns the hash string from the given password. The function
// automatically generates a random salt and uses predefined parameters for the
// Argon2id algorithm.
func Hash(password string) string {
	salt, err := generateRandomSalt(16)
	if err != nil {
		return ""
	}
	p := Param{
		Salt:    salt,
		Time:    1,
		Memory:  64 * 1024,
		Threads: uint8(runtime.NumCPU()),
		KeyLen:  32,
	}
	return Stringify(
		argon2.IDKey(
			[]byte(password),
			p.Salt,
			p.Time,
			p.Memory,
			p.Threads,
			p.KeyLen,
		),
		&p,
	)
}

// Verify returns `true` if the password matches the hash, and `false`
// otherwise.
func Verify(password string, hash string) bool {
	key, p, err := Parse(hash)
	if err != nil {
		return false
	}
	newKey := argon2.IDKey(
		[]byte(password),
		p.Salt,
		p.Time,
		p.Memory,
		p.Threads,
		p.KeyLen,
	)
	return subtle.ConstantTimeCompare(key, newKey) == 1
}

type Param struct {
	Salt    []byte
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

var (
	// ErrInvalidEncodedHash indicates that the encoded hash is invalid.
	ErrInvalidEncodedHash = errors.New("invalid encoded hash")

	// ErrVersionMismatch indicates that there is a version mismatch between the
	// hash and the current Argon2 version.
	ErrVersionMismatch = errors.New("version mismatch")
)

func Stringify(key []byte, p *Param) string {
	return fmt.Sprintf(
		"$argon2id$v=%v$m=%v,t=%v,p=%v$%v$%v",
		argon2.Version,
		p.Memory,
		p.Time,
		p.Threads,
		encoder.EncodeToString(p.Salt),
		encoder.EncodeToString(key),
	)
}

func Parse(s string) ([]byte, Param, error) {
	re := regexp.MustCompile(
		`^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$(.+)$`,
	)
	matches := re.FindStringSubmatch(s)
	if len(matches) != 7 {
		return nil, Param{}, ErrInvalidEncodedHash
	}
	version, err := strconv.Atoi(matches[1])
	if err != nil {
		return nil, Param{}, err
	}
	if version != argon2.Version {
		return nil, Param{}, ErrVersionMismatch
	}
	memory, err := strconv.Atoi(matches[2])
	if err != nil {
		return nil, Param{}, err
	}
	time, err := strconv.Atoi(matches[3])
	if err != nil {
		return nil, Param{}, err
	}
	threads, err := strconv.Atoi(matches[4])
	if err != nil {
		return nil, Param{}, err
	}
	salt, err := encoder.DecodeString(matches[5])
	if err != nil {
		return nil, Param{}, err
	}
	key, err := encoder.DecodeString(matches[6])
	if err != nil {
		return nil, Param{}, err
	}
	return key, Param{
		Salt:    salt,
		Time:    uint32(time),
		Memory:  uint32(memory),
		Threads: uint8(threads),
		KeyLen:  uint32(len(key)),
	}, nil
}

var encoder = base64.RawStdEncoding.Strict()

func generateRandomSalt(length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	return buf, err
}
