package clickhouse

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockSignFunc(token string) func(string) (string, error) {
	return func(queryBody string) (string, error) {
		return token + ":" + queryBody, nil
	}
}

func mockSignFuncError(errMsg string) func(string) (string, error) {
	return func(queryBody string) (string, error) {
		return "", fmt.Errorf("%s", errMsg)
	}
}

func TestResolveSignFunc_ContextOverridesConnection(t *testing.T) {
	connSign := mockSignFunc("conn")
	ctxSign := mockSignFunc("ctx")

	c := &connect{
		opt: &Options{
			SignFunc: connSign,
		},
	}

	opts := &QueryOptions{signFunc: ctxSign}
	resolved := c.resolveSignFunc(opts)
	require.NotNil(t, resolved)

	// Context sign func should take precedence
	token, err := resolved("SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, "ctx:SELECT 1", token)
}

func TestResolveSignFunc_FallbackToConnection(t *testing.T) {
	connSign := mockSignFunc("conn")

	c := &connect{
		opt: &Options{
			SignFunc: connSign,
		},
	}

	opts := &QueryOptions{}
	resolved := c.resolveSignFunc(opts)
	require.NotNil(t, resolved)

	token, err := resolved("SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, "conn:SELECT 1", token)
}

func TestResolveSignFunc_NilWhenNoFunc(t *testing.T) {
	c := &connect{
		opt: &Options{},
	}

	opts := &QueryOptions{}
	resolved := c.resolveSignFunc(opts)
	assert.Nil(t, resolved)
}

func TestWithSignFunc(t *testing.T) {
	signFunc := mockSignFunc("test")
	opt := WithSignFunc(signFunc)

	opts := &QueryOptions{}
	err := opt(opts)
	require.NoError(t, err)
	require.NotNil(t, opts.signFunc)

	token, err := opts.signFunc("SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, "test:SELECT 1", token)
}
