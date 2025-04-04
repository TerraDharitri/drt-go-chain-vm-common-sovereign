package builtInFunctions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func getWhiteListedAddress() map[string]struct{} {
	return map[string]struct{}{
		"whiteListedAddress": {},
	}
}

func TestNewCrossChainTokenChecker(t *testing.T) {
	t.Parallel()

	t.Run("main chain, should work", func(t *testing.T) {
		ctc, err := NewCrossChainTokenChecker([]byte{}, getWhiteListedAddress())
		require.Nil(t, err)
		require.False(t, ctc.IsInterfaceNil())
	})

	t.Run("sovereign chain valid prefix, should work", func(t *testing.T) {
		ctc, err := NewCrossChainTokenChecker([]byte("pref"), getWhiteListedAddress())
		require.Nil(t, err)
		require.False(t, ctc.IsInterfaceNil())
	})

	t.Run("sovereign chain with invalid prefix, should not work", func(t *testing.T) {
		ctc, err := NewCrossChainTokenChecker([]byte("PREFIX"), getWhiteListedAddress())
		require.ErrorIs(t, err, ErrInvalidTokenPrefix)
		require.Nil(t, ctc)
	})

	t.Run("no whitelisted address, should not work", func(t *testing.T) {
		ctc, err := NewCrossChainTokenChecker([]byte("PREFIX"), nil)
		require.ErrorIs(t, err, ErrNoWhiteListedAddressCrossChainOperations)
		require.Nil(t, ctc)

		ctc, err = NewCrossChainTokenChecker(nil, nil)
		require.ErrorIs(t, err, ErrNoWhiteListedAddressCrossChainOperations)
		require.Nil(t, ctc)
	})
}

func TestCrossChainTokenChecker_IsCrossChainOperation(t *testing.T) {
	t.Parallel()

	t.Run("cross chain operations in a sovereign shard", func(t *testing.T) {
		ctc, _ := NewCrossChainTokenChecker([]byte("sov1"), getWhiteListedAddress())

		require.True(t, ctc.IsCrossChainOperation([]byte("ALICE-abcdef")))
		require.True(t, ctc.IsCrossChainOperation([]byte("sov2-ALICE-abcdef")))
		require.False(t, ctc.IsCrossChainOperation([]byte("sov1-ALICE-abcdef")))
	})

	t.Run("cross chain operations in a main chain", func(t *testing.T) {
		ctc, _ := NewCrossChainTokenChecker(nil, getWhiteListedAddress())

		require.True(t, ctc.IsCrossChainOperation([]byte("sov2-ALICE-abcdef")))
		require.True(t, ctc.IsCrossChainOperation([]byte("sov1-ALICE-abcdef")))
		require.False(t, ctc.IsCrossChainOperation([]byte("ALICE-abcdef")))
	})
}

func TestCrossChainTokenChecker_isWhiteListed(t *testing.T) {
	t.Parallel()

	whiteListedAddr1 := "whiteListedAddress1"
	whiteListedAddr2 := "whiteListedAddress2"
	whiteListedAddresses := map[string]struct{}{
		whiteListedAddr1: {},
		whiteListedAddr2: {},
	}
	ctc, _ := NewCrossChainTokenChecker(nil, whiteListedAddresses)

	require.True(t, ctc.isWhiteListed([]byte(whiteListedAddr1)))
	require.True(t, ctc.isWhiteListed([]byte(whiteListedAddr2)))
	require.False(t, ctc.isWhiteListed([]byte("addr3")))
	require.False(t, ctc.isWhiteListed(nil))
}

func TestCrossChainTokenChecker_IsCrossChainOperationAllowed(t *testing.T) {
	t.Parallel()

	whiteListAddr := []byte("whiteListedAddress")
	t.Run("main chain", func(t *testing.T) {
		ctc, _ := NewCrossChainTokenChecker(nil, getWhiteListedAddress())

		require.True(t, ctc.IsCrossChainOperationAllowed(whiteListAddr, []byte("sov1-ALICE-abcdef")))
		require.False(t, ctc.IsCrossChainOperationAllowed([]byte("anotherAddress"), []byte("sov1-ALICE-abcdef")))
		require.False(t, ctc.IsCrossChainOperationAllowed(whiteListAddr, []byte("ALICE-abcdef")))
		require.False(t, ctc.IsCrossChainOperationAllowed([]byte("anotherAddress"), []byte("ALICE-abcdef")))
	})

	t.Run("single shard chain", func(t *testing.T) {
		ctc, _ := NewCrossChainTokenChecker([]byte("pref"), getWhiteListedAddress())

		require.True(t, ctc.IsCrossChainOperationAllowed(whiteListAddr, []byte("sov1-ALICE-abcdef")))
		require.True(t, ctc.IsCrossChainOperationAllowed(whiteListAddr, []byte("ALICE-abcdef")))
		require.False(t, ctc.IsCrossChainOperationAllowed([]byte("anotherAddress"), []byte("sov1-ALICE-abcdef")))
		require.False(t, ctc.IsCrossChainOperationAllowed(whiteListAddr, []byte("pref-ALICE-abcdef")))
	})
}
