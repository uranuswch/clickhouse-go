package clickhouse

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwsPayload struct {
	Iat       int64  `json:"iat"`
	QueryHash string `json:"qhash"`
}

const (
	ethereumRecoveryIDOffset = 27
	ethereumSignatureLength  = 65
)

var (
	jwsHeaderV1        = jwsHeader{Alg: "ES256K", Typ: "JWS"}
	jwsHeaderBase64URL string
)

func init() {
	headerBytes, _ := json.Marshal(jwsHeaderV1)
	jwsHeaderBase64URL = base64.RawURLEncoding.EncodeToString(headerBytes)
}

func keccak256Hex(data []byte) string {
	return "0x" + hex.EncodeToString(crypto.Keccak256(data))
}

func signQuery(body string, privateKey *ecdsa.PrivateKey) (string, error) {
	payloadBytes, err := json.Marshal(jwsPayload{
		Iat:       time.Now().Unix(),
		QueryHash: keccak256Hex([]byte(body)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWS payload: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := jwsHeaderBase64URL + "." + payloadB64
	msgHash := crypto.Keccak256([]byte(signingInput))

	sig, err := crypto.Sign(msgHash, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign query: %w", err)
	}

	if len(sig) != ethereumSignatureLength {
		return "", fmt.Errorf("invalid signature length: expected %d, got %d", ethereumSignatureLength, len(sig))
	}

	recoveryID := sig[64]
	if recoveryID > 1 {
		return "", fmt.Errorf("invalid recovery ID: expected 0 or 1, got %d", recoveryID)
	}

	ethSig := make([]byte, ethereumSignatureLength)
	copy(ethSig, sig)
	ethSig[64] = recoveryID + ethereumRecoveryIDOffset

	sigB64 := base64.RawURLEncoding.EncodeToString(ethSig)
	return signingInput + "." + sigB64, nil
}
