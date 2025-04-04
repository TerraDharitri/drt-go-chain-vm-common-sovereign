package builtInFunctions

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-core/data/dcdt"
	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
	"github.com/TerraDharitri/drt-go-chain-vm-common/mock"
	"github.com/stretchr/testify/require"
)

func TestNewDCDTRolesFunc(t *testing.T) {
	t.Parallel()

	t.Run("should work", func(t *testing.T) {
		dcdtRolesF, err := NewDCDTRolesFunc(&mock.MarshalizerMock{}, &mock.CrossChainTokenCheckerMock{}, false)
		require.Nil(t, err)
		require.False(t, dcdtRolesF.IsInterfaceNil())
		require.Equal(t, map[string]struct{}{
			core.DCDTRoleLocalMint:      {},
			core.DCDTRoleNFTAddQuantity: {},
			core.DCDTRoleNFTCreate:      {},
			core.DCDTRoleLocalBurn:      {},
			core.DCDTRoleNFTBurn:        {},
		}, dcdtRolesF.crossChainActions)
	})
	t.Run("nil marshaller, should return error", func(t *testing.T) {
		dcdtRolesF, err := NewDCDTRolesFunc(nil, &mock.CrossChainTokenCheckerMock{}, false)
		require.Equal(t, ErrNilMarshalizer, err)
		require.Nil(t, dcdtRolesF)
	})
	t.Run("nil cross chain checker, should return error", func(t *testing.T) {
		dcdtRolesF, err := NewDCDTRolesFunc(&mock.MarshalizerMock{}, nil, false)
		require.Equal(t, ErrNilCrossChainTokenChecker, err)
		require.Nil(t, dcdtRolesF)
	})
}

func TestDcdtRoles_ProcessBuiltinFunction_NilVMInputShouldErr(t *testing.T) {
	t.Parallel()

	dcdtRolesF, _ := NewDCDTRolesFunc(nil, &mock.CrossChainTokenCheckerMock{}, false)

	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, &mock.UserAccountStub{}, nil)
	require.Equal(t, ErrNilVmInput, err)
}

func TestDcdtRoles_ProcessBuiltinFunction_WrongCalledShouldErr(t *testing.T) {
	t.Parallel()

	dcdtRolesF, _ := NewDCDTRolesFunc(nil, &mock.CrossChainTokenCheckerMock{}, false)

	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, &mock.UserAccountStub{}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			CallerAddr: []byte{},
			Arguments:  [][]byte{[]byte("1"), []byte("2")},
		},
	})
	require.Equal(t, ErrAddressIsNotDCDTSystemSC, err)
}

func TestDcdtRoles_ProcessBuiltinFunction_NilAccountDestShouldErr(t *testing.T) {
	t.Parallel()

	dcdtRolesF, _ := NewDCDTRolesFunc(nil, &mock.CrossChainTokenCheckerMock{}, false)

	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			CallerAddr: core.DCDTSCAddress,
			Arguments:  [][]byte{[]byte("1"), []byte("2")},
		},
	})
	require.Equal(t, ErrNilUserAccount, err)
}

func TestDcdtRoles_ProcessBuiltinFunction_GetRolesFailShouldErr(t *testing.T) {
	t.Parallel()

	dcdtRolesF, _ := NewDCDTRolesFunc(&mock.MarshalizerMock{Fail: true}, &mock.CrossChainTokenCheckerMock{}, false)

	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					return nil, 0, nil
				},
			}
		},
	}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			CallerAddr: core.DCDTSCAddress,
			Arguments:  [][]byte{[]byte("1"), []byte("2")},
		},
	})
	require.Error(t, err)
}

func TestDcdtRoles_ProcessBuiltinFunction_GetRolesFailShouldWorkEvenIfAccntTrieIsNil(t *testing.T) {
	t.Parallel()

	saveKeyWasCalled := false
	dcdtRolesF, _ := NewDCDTRolesFunc(&mock.MarshalizerMock{}, &mock.CrossChainTokenCheckerMock{}, false)

	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					return nil, 0, nil
				},
				SaveKeyValueCalled: func(_ []byte, _ []byte) error {
					saveKeyWasCalled = true
					return nil
				},
			}
		},
	}, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			CallerAddr: core.DCDTSCAddress,
			Arguments:  [][]byte{[]byte("1"), []byte("2")},
		},
	})
	require.NoError(t, err)
	require.True(t, saveKeyWasCalled)
}

func TestDcdtRoles_ProcessBuiltinFunction_SetRolesShouldWork(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, true)

	acc := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					roles := &dcdt.DCDTRoles{}
					serializedRoles, err := marshaller.Marshal(roles)
					return serializedRoles, 0, err
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					roles := &dcdt.DCDTRoles{}
					_ = marshaller.Unmarshal(roles, value)
					require.Equal(t, roles.Roles, [][]byte{[]byte(core.DCDTRoleLocalMint)})
					return nil
				},
			}
		},
	}
	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, acc, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			CallerAddr: core.DCDTSCAddress,
			Arguments:  [][]byte{[]byte("1"), []byte(core.DCDTRoleLocalMint)},
		},
	})
	require.Nil(t, err)
}

func TestDcdtRoles_ProcessBuiltinFunction_SetRolesMultiNFT(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, true)

	tokenID := []byte("tokenID")
	roleKey := append(roleKeyPrefix, tokenID...)

	saveNonceCalled := false
	acc := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					roles := &dcdt.DCDTRoles{}
					serializedRoles, err := marshaller.Marshal(roles)
					return serializedRoles, 0, err
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					if bytes.Equal(key, roleKey) {
						roles := &dcdt.DCDTRoles{}
						_ = marshaller.Unmarshal(roles, value)
						require.Equal(t, roles.Roles, [][]byte{[]byte(core.DCDTRoleNFTCreate), []byte(core.DCDTRoleNFTCreateMultiShard)})
						return nil
					}

					if bytes.Equal(key, getNonceKey(tokenID)) {
						saveNonceCalled = true
						require.Equal(t, uint64(math.MaxUint64/256), big.NewInt(0).SetBytes(value).Uint64())
					}

					return nil
				},
			}
		},
	}
	dstAddr := bytes.Repeat([]byte{1}, 32)
	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, acc, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			CallerAddr: core.DCDTSCAddress,
			Arguments:  [][]byte{tokenID, []byte(core.DCDTRoleNFTCreate), []byte(core.DCDTRoleNFTCreateMultiShard)},
		},
		RecipientAddr: dstAddr,
	})

	require.Nil(t, err)
	require.True(t, saveNonceCalled)
}

func TestDcdtRoles_ProcessBuiltinFunction_SaveFailedShouldErr(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, true)

	localErr := errors.New("local err")
	acc := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					roles := &dcdt.DCDTRoles{}
					serializedRoles, err := marshaller.Marshal(roles)
					return serializedRoles, 0, err
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					return localErr
				},
			}
		},
	}
	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, acc, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			CallerAddr: core.DCDTSCAddress,
			Arguments:  [][]byte{[]byte("1"), []byte(core.DCDTRoleLocalMint)},
		},
	})
	require.Equal(t, localErr, err)
}

func TestDcdtRoles_ProcessBuiltinFunction_UnsetRolesDoesNotExistsShouldWork(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, false)

	acc := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					roles := &dcdt.DCDTRoles{}
					serializedRoles, err := marshaller.Marshal(roles)
					return serializedRoles, 0, err
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					roles := &dcdt.DCDTRoles{}
					_ = marshaller.Unmarshal(roles, value)
					require.Len(t, roles.Roles, 0)
					return nil
				},
			}
		},
	}
	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, acc, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			CallerAddr: core.DCDTSCAddress,
			Arguments:  [][]byte{[]byte("1"), []byte(core.DCDTRoleLocalMint)},
		},
	})
	require.Nil(t, err)
}

func TestDcdtRoles_ProcessBuiltinFunction_UnsetRolesShouldWork(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, false)

	acc := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					roles := &dcdt.DCDTRoles{
						Roles: [][]byte{[]byte(core.DCDTRoleLocalMint)},
					}
					serializedRoles, err := marshaller.Marshal(roles)
					return serializedRoles, 0, err
				},
				SaveKeyValueCalled: func(key []byte, value []byte) error {
					roles := &dcdt.DCDTRoles{}
					_ = marshaller.Unmarshal(roles, value)
					require.Len(t, roles.Roles, 0)
					return nil
				},
			}
		},
	}
	_, err := dcdtRolesF.ProcessBuiltinFunction(nil, acc, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue:  big.NewInt(0),
			CallerAddr: core.DCDTSCAddress,
			Arguments:  [][]byte{[]byte("1"), []byte(core.DCDTRoleLocalMint)},
		},
	})
	require.Nil(t, err)
}

func TestDcdtRoles_CheckAllowedToExecuteNilAccountShouldErr(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, false)

	err := dcdtRolesF.CheckAllowedToExecute(nil, []byte("ID"), []byte(core.DCDTRoleLocalBurn))
	require.Equal(t, ErrNilUserAccount, err)
}

func TestDcdtRoles_CheckAllowedToExecuteCannotGetDCDTRole(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{Fail: true}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, false)

	err := dcdtRolesF.CheckAllowedToExecute(&mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					return nil, 0, nil
				},
			}
		},
	}, []byte("ID"), []byte(core.DCDTRoleLocalBurn))
	require.Error(t, err)
}

func TestDcdtRoles_CheckAllowedToExecuteIsNewNotAllowed(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, false)

	err := dcdtRolesF.CheckAllowedToExecute(&mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					return nil, 0, nil
				},
			}
		},
	}, []byte("ID"), []byte(core.DCDTRoleLocalBurn))
	require.Equal(t, ErrActionNotAllowed, err)
}

func TestDcdtRoles_CheckAllowed_ShouldWork(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, false)

	err := dcdtRolesF.CheckAllowedToExecute(&mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					roles := &dcdt.DCDTRoles{
						Roles: [][]byte{[]byte(core.DCDTRoleLocalMint)},
					}
					serializedRoles, err := marshaller.Marshal(roles)
					return serializedRoles, 0, err
				},
			}
		},
	}, []byte("ID"), []byte(core.DCDTRoleLocalMint))
	require.Nil(t, err)
}

func TestDcdtRoles_CheckAllowedToExecuteRoleNotFind(t *testing.T) {
	t.Parallel()

	marshaller := &mock.MarshalizerMock{}
	dcdtRolesF, _ := NewDCDTRolesFunc(marshaller, &mock.CrossChainTokenCheckerMock{}, false)

	err := dcdtRolesF.CheckAllowedToExecute(&mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
					roles := &dcdt.DCDTRoles{
						Roles: [][]byte{[]byte(core.DCDTRoleLocalBurn)},
					}
					serializedRoles, err := marshaller.Marshal(roles)
					return serializedRoles, 0, err
				},
			}
		},
	}, []byte("ID"), []byte(core.DCDTRoleLocalMint))
	require.Equal(t, ErrActionNotAllowed, err)
}

func TestDcdtRoles_isAllowedToExecuteCrossChain(t *testing.T) {
	isCrossChainOperationAllowedCt := 0
	ctc := &mock.CrossChainTokenCheckerMock{
		IsCrossChainOperationAllowedCalled: func(address []byte, tokenID []byte) bool {
			isCrossChainOperationAllowedCt++
			return true
		},
	}
	dcdtRolesF, _ := NewDCDTRolesFunc(&mock.MarshalizerMock{}, ctc, false)

	isAllowed := dcdtRolesF.isAllowedToExecuteCrossChain([]byte("addr"), []byte("token"), []byte(core.DCDTRoleLocalBurn))
	require.True(t, isAllowed)
	require.Equal(t, 1, isCrossChainOperationAllowedCt)

	isAllowed = dcdtRolesF.isAllowedToExecuteCrossChain([]byte("addr"), []byte("token"), []byte(core.DCDTRoleNFTAddQuantity))
	require.True(t, isAllowed)
	require.Equal(t, 2, isCrossChainOperationAllowedCt)

	isAllowed = dcdtRolesF.isAllowedToExecuteCrossChain([]byte("addr"), []byte("token"), []byte(core.DCDTRoleModifyRoyalties))
	require.False(t, isAllowed)
	require.Equal(t, 2, isCrossChainOperationAllowedCt)
}
