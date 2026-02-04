package clickhouse

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	return key
}

func TestSignQuery_TokenStructure(t *testing.T) {
	key := generateTestKey(t)
	token, err := signQuery("SELECT 1", key)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3, "JWS token must have 3 parts: header.payload.signature")

	// Each part must be valid base64url
	for i, part := range parts {
		_, err := base64.RawURLEncoding.DecodeString(part)
		assert.NoError(t, err, "part %d is not valid base64url", i)
	}
}

func TestSignQuery_Header(t *testing.T) {
	key := generateTestKey(t)
	token, err := signQuery("SELECT 1", key)
	require.NoError(t, err)

	headerB64 := strings.Split(token, ".")[0]
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	require.NoError(t, err)

	var header jwsHeader
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "ES256K", header.Alg)
	assert.Equal(t, "JWS", header.Typ)
}

func TestSignQuery_Payload(t *testing.T) {
	key := generateTestKey(t)
	query := "SELECT * FROM users WHERE id = 1"
	token, err := signQuery(query, key)
	require.NoError(t, err)

	payloadB64 := strings.Split(token, ".")[1]
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	require.NoError(t, err)

	var payload jwsPayload
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))
	assert.Greater(t, payload.Iat, int64(0), "iat must be a positive unix timestamp")
	assert.True(t, strings.HasPrefix(payload.QueryHash, "0x"), "qhash must have 0x prefix")
	assert.Len(t, payload.QueryHash, 66, "keccak256 hex should be 0x + 64 hex chars")

	// Verify the hash matches the query
	expectedHash := keccak256Hex([]byte(query))
	assert.Equal(t, expectedHash, payload.QueryHash)
}

func TestSignQuery_SignatureVerification(t *testing.T) {
	key := generateTestKey(t)
	token, err := signQuery("SELECT 1", key)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	assert.Len(t, sigBytes, ethereumSignatureLength)

	// Undo Ethereum recovery ID offset
	recoveryID := sigBytes[64] - ethereumRecoveryIDOffset
	assert.True(t, recoveryID == 0 || recoveryID == 1)

	// Reconstruct original signature for verification
	sigForRecover := make([]byte, ethereumSignatureLength)
	copy(sigForRecover, sigBytes)
	sigForRecover[64] = recoveryID

	// Recover public key from signature
	msgHash := crypto.Keccak256([]byte(signingInput))
	recoveredPub, err := crypto.Ecrecover(msgHash, sigForRecover)
	require.NoError(t, err)

	// Compare with original public key
	expectedPub := crypto.FromECDSAPub(&key.PublicKey)
	assert.Equal(t, expectedPub, recoveredPub)
}

func TestSignQuery_DifferentQueries(t *testing.T) {
	key := generateTestKey(t)
	token1, err := signQuery("SELECT 1", key)
	require.NoError(t, err)
	token2, err := signQuery("SELECT 2", key)
	require.NoError(t, err)

	// Tokens should differ (different query hash)
	assert.NotEqual(t, token1, token2)

	// Headers should be the same
	assert.Equal(t, strings.Split(token1, ".")[0], strings.Split(token2, ".")[0])
}

func TestSignQuery_DifferentKeys(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)
	query := "SELECT 1"

	token1, err := signQuery(query, key1)
	require.NoError(t, err)
	token2, err := signQuery(query, key2)
	require.NoError(t, err)

	// Signatures should differ (different keys)
	sig1 := strings.Split(token1, ".")[2]
	sig2 := strings.Split(token2, ".")[2]
	assert.NotEqual(t, sig1, sig2)
}

func TestResolveSigningKey_ContextOverridesConnection(t *testing.T) {
	connKey := generateTestKey(t)
	ctxKey := generateTestKey(t)

	c := &connect{
		opt: &Options{
			SigningKey: connKey,
		},
	}

	// Context key should take precedence
	opts := &QueryOptions{signingKey: ctxKey}
	resolved := c.resolveSigningKey(opts)
	assert.Equal(t, ctxKey, resolved)
}

func TestResolveSigningKey_FallbackToConnection(t *testing.T) {
	connKey := generateTestKey(t)

	c := &connect{
		opt: &Options{
			SigningKey: connKey,
		},
	}

	// No context key → fall back to connection key
	opts := &QueryOptions{}
	resolved := c.resolveSigningKey(opts)
	assert.Equal(t, connKey, resolved)
}

func TestResolveSigningKey_NilWhenNoKey(t *testing.T) {
	c := &connect{
		opt: &Options{},
	}

	opts := &QueryOptions{}
	resolved := c.resolveSigningKey(opts)
	assert.Nil(t, resolved)
}
