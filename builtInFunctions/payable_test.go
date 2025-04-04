package builtInFunctions

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-core/data/vm"
	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
	"github.com/TerraDharitri/drt-go-chain-vm-common/mock"
	"github.com/stretchr/testify/assert"
)

func createMockPayableChecker(isFixAsyncCallbackCheckFlagEnabledField, isCheckFunctionArgumentFlagEnabled bool) *payableCheck {
	p, _ := NewPayableCheckFunc(
		&mock.PayableHandlerStub{},
		&mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				switch flag {
				case FixAsyncCallbackCheckFlag:
					return isFixAsyncCallbackCheckFlagEnabledField
				case CheckFunctionArgumentFlag:
					return isCheckFunctionArgumentFlagEnabled
				default:
					return false
				}
			},
		})
	return p
}

func TestNewPayableCheckFunc(t *testing.T) {
	t.Parallel()

	_, err := NewPayableCheckFunc(nil, &mock.EnableEpochsHandlerStub{})
	assert.Equal(t, err, ErrNilPayableHandler)

	_, err = NewPayableCheckFunc(&mock.PayableHandlerStub{}, nil)
	assert.Equal(t, err, ErrNilEnableEpochsHandler)

	p := createMockPayableChecker(false, false)
	assert.False(t, p.IsInterfaceNil())
}

func TestDetermineIsSCCallAfter(t *testing.T) {
	t.Parallel()

	scAddress, _ := hex.DecodeString("00000000000000000500e9a061848044cc9c6ac2d78dca9e4f72e72a0a5b315c")
	address, _ := hex.DecodeString("432d6fed4f1d8ac43cd3201fd047b98e27fc9c06efb20c6593ba577cd11228ab")
	p1 := createMockPayableChecker(true, true)
	p2 := createMockPayableChecker(false, false)
	minLenArguments := 4
	t.Run("less number of arguments should return false", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: make([][]byte, 0),
			},
		}

		for i := 0; i < minLenArguments; i++ {
			assert.False(t, p1.DetermineIsSCCallAfter(vmInput, scAddress, minLenArguments))
			assert.False(t, p2.DetermineIsSCCallAfter(vmInput, scAddress, minLenArguments))
		}
	})
	t.Run("ReturnCallAfterError should return false", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments:            [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3"), []byte("arg4"), []byte("arg5")},
				CallType:             vm.AsynchronousCall,
				ReturnCallAfterError: true,
			},
		}

		assert.False(t, p1.DetermineIsSCCallAfter(vmInput, address, minLenArguments))
		assert.False(t, p2.DetermineIsSCCallAfter(vmInput, address, minLenArguments))
	})
	t.Run("not a sc address should return false", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3"), []byte("arg4"), []byte("arg5")},
			},
		}

		assert.False(t, p1.DetermineIsSCCallAfter(vmInput, address, minLenArguments))
		assert.False(t, p2.DetermineIsSCCallAfter(vmInput, address, minLenArguments))
	})
	t.Run("empty last argument", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3"), []byte("arg4"), []byte("")},
			},
		}
		assert.False(t, p1.DetermineIsSCCallAfter(vmInput, scAddress, minLenArguments))
		assert.True(t, p2.DetermineIsSCCallAfter(vmInput, scAddress, minLenArguments))
	})
	t.Run("should work", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3"), []byte("arg4"), []byte("arg5")},
			},
		}
		t.Run("ReturnCallAfterError == false", func(t *testing.T) {
			assert.True(t, p1.DetermineIsSCCallAfter(vmInput, scAddress, minLenArguments))
			assert.True(t, p2.DetermineIsSCCallAfter(vmInput, scAddress, minLenArguments))
		})
		t.Run("ReturnCallAfterError == true and CallType == AsynchronousCallBack", func(t *testing.T) {
			vmInput.CallType = vm.AsynchronousCallBack
			vmInput.ReturnCallAfterError = true
			assert.True(t, p1.DetermineIsSCCallAfter(vmInput, scAddress, minLenArguments))
			assert.True(t, p2.DetermineIsSCCallAfter(vmInput, scAddress, minLenArguments))
		})
	})
}

func TestMustVerifyPayable(t *testing.T) {
	t.Parallel()

	minLenArguments := 4
	p1 := createMockPayableChecker(true, true)
	p2 := createMockPayableChecker(false, false)

	t.Run("call type is AsynchronousCall should return false", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3")},
				CallType:  vm.AsynchronousCall,
			},
		}

		assert.True(t, p1.mustVerifyPayable(vmInput, minLenArguments))
		assert.False(t, p2.mustVerifyPayable(vmInput, minLenArguments))
	})
	t.Run("call type is AsynchronousCall should return false", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3")},
				CallType:  vm.AsynchronousCallBack,
			},
		}

		assert.False(t, p1.mustVerifyPayable(vmInput, minLenArguments))
		assert.True(t, p2.mustVerifyPayable(vmInput, minLenArguments))
	})
	t.Run("call type is DCDTTransferAndExecute should return false", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3")},
				CallType:  vm.DCDTTransferAndExecute,
			},
		}

		assert.False(t, p1.mustVerifyPayable(vmInput, minLenArguments))
		assert.False(t, p2.mustVerifyPayable(vmInput, minLenArguments))
	})
	t.Run("return after error should return true for bckwd, false for new", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments:            [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3")},
				CallType:             vm.DirectCall,
				ReturnCallAfterError: true,
			},
		}

		assert.False(t, p1.mustVerifyPayable(vmInput, minLenArguments))
		assert.True(t, p2.mustVerifyPayable(vmInput, minLenArguments))
	})
	t.Run("arguments represents a SC call should return false", func(t *testing.T) {
		t.Run("5 arguments", func(t *testing.T) {
			vmInput := &vmcommon.ContractCallInput{
				VMInput: vmcommon.VMInput{
					Arguments: [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3"), []byte("arg4"), []byte("arg5")},
					CallType:  vm.DirectCall,
				},
			}
			assert.False(t, p1.mustVerifyPayable(vmInput, minLenArguments))
			assert.False(t, p2.mustVerifyPayable(vmInput, minLenArguments))
		})
		t.Run("6 arguments", func(t *testing.T) {
			vmInput := &vmcommon.ContractCallInput{
				VMInput: vmcommon.VMInput{
					Arguments: [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3"), []byte("arg4"), []byte("arg5"), []byte("arg6")},
					CallType:  vm.DirectCall,
				},
			}
			assert.False(t, p1.mustVerifyPayable(vmInput, minLenArguments))
			assert.False(t, p2.mustVerifyPayable(vmInput, minLenArguments))
		})
	})
	t.Run("caller is DCDT address should return false", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments:  [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3")},
				CallType:   vm.DirectCall,
				CallerAddr: core.DCDTSCAddress,
			},
		}

		assert.False(t, p1.mustVerifyPayable(vmInput, minLenArguments))
		assert.False(t, p2.mustVerifyPayable(vmInput, minLenArguments))
	})
	t.Run("should return true", func(t *testing.T) {
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3")},
			},
		}

		t.Run("call type is DirectCall", func(t *testing.T) {
			vmInput.CallType = vm.DirectCall
			assert.True(t, p1.mustVerifyPayable(vmInput, minLenArguments))
			assert.True(t, p2.mustVerifyPayable(vmInput, minLenArguments))
		})
		t.Run("call type is AsynchronousCallBack", func(t *testing.T) {
			vmInput.CallType = vm.AsynchronousCallBack
			assert.False(t, p1.mustVerifyPayable(vmInput, minLenArguments))
			assert.True(t, p2.mustVerifyPayable(vmInput, minLenArguments))
		})
		t.Run("call type is ExecOnDestByCaller", func(t *testing.T) {
			vmInput.CallType = vm.ExecOnDestByCaller
			assert.True(t, p1.mustVerifyPayable(vmInput, minLenArguments))
			assert.True(t, p2.mustVerifyPayable(vmInput, minLenArguments))
		})
		t.Run("equal arguments than minimum", func(t *testing.T) {
			vmInput.Arguments = [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3"), []byte("arg4")}
			vmInput.CallType = vm.ExecOnDestByCaller
			assert.True(t, p1.mustVerifyPayable(vmInput, minLenArguments))
			assert.True(t, p2.mustVerifyPayable(vmInput, minLenArguments))
		})
		t.Run("5 arguments but no function", func(t *testing.T) {
			vmInput.Arguments = [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3"), []byte("arg4"), make([]byte, 0)}
			vmInput.CallType = vm.ExecOnDestByCaller
			assert.True(t, p1.mustVerifyPayable(vmInput, minLenArguments))
			t.Run("backwards compatibility", func(t *testing.T) {
				assert.False(t, p2.mustVerifyPayable(vmInput, minLenArguments))
			})
		})
	})
}

func TestPayableCheck_CheckPayable(t *testing.T) {
	t.Parallel()

	p := createMockPayableChecker(true, true)
	p.payableHandler = &mock.PayableHandlerStub{
		IsPayableCalled: func(address []byte) (bool, error) {
			return false, nil
		}}

	scAddress, _ := hex.DecodeString("00000000000000000500e9a061848044cc9c6ac2d78dca9e4f72e72a0a5b315c")
	vmInput := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			Arguments:  [][]byte{[]byte("arg1"), []byte("arg2"), []byte("arg3")},
			CallerAddr: scAddress,
		},
		RecipientAddr: scAddress,
	}
	err := p.CheckPayable(vmInput, scAddress, 5)
	assert.Equal(t, err, ErrAccountNotPayable)

	localErr := errors.New("localErr")
	p.payableHandler = &mock.PayableHandlerStub{
		IsPayableCalled: func(address []byte) (bool, error) {
			return true, localErr
		}}
	err = p.CheckPayable(vmInput, scAddress, 5)
	assert.Equal(t, err, localErr)

	err = p.CheckPayable(vmInput, scAddress, 2)
	assert.Nil(t, err)

	p.payableHandler = &mock.PayableHandlerStub{
		IsPayableCalled: func(address []byte) (bool, error) {
			return true, nil
		}}
	err = p.CheckPayable(vmInput, scAddress, 5)
	assert.Nil(t, err)
}
