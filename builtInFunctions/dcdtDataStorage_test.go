package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/TerraDharitri/drt-go-chain-core/core"
	"github.com/TerraDharitri/drt-go-chain-core/data/dcdt"
	"github.com/TerraDharitri/drt-go-chain-core/data/smartContractResult"
	"github.com/stretchr/testify/assert"

	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
	"github.com/TerraDharitri/drt-go-chain-vm-common/mock"
)

func createNewDCDTDataStorageHandler() *dcdtDataStorage {
	acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
	accounts := &mock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
		return acnt, nil
	}}
	args := ArgsNewDCDTDataStorage{
		Accounts:              accounts,
		GlobalSettingsHandler: &mock.GlobalSettingsHandlerStub{},
		Marshalizer:           &mock.MarshalizerMock{},
		EnableEpochsHandler: &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag
			},
		},
		ShardCoordinator:              &mock.ShardCoordinatorStub{},
		CrossChainTokenCheckerHandler: &mock.CrossChainTokenCheckerMock{},
	}
	dataStore, _ := NewDCDTDataStorage(args)
	return dataStore
}

func createMockArgsForNewDCDTDataStorage() ArgsNewDCDTDataStorage {
	acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
	accounts := &mock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
		return acnt, nil
	}}
	args := ArgsNewDCDTDataStorage{
		Accounts:              accounts,
		GlobalSettingsHandler: &mock.GlobalSettingsHandlerStub{},
		Marshalizer:           &mock.MarshalizerMock{},
		EnableEpochsHandler: &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag
			},
		},
		ShardCoordinator:              &mock.ShardCoordinatorStub{},
		CrossChainTokenCheckerHandler: &mock.CrossChainTokenCheckerMock{},
	}
	return args
}

func createNewDCDTDataStorageHandlerWithArgs(
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
	accounts vmcommon.AccountsAdapter,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	crossChainTokenChecker CrossChainTokenCheckerHandler,
) *dcdtDataStorage {
	args := ArgsNewDCDTDataStorage{
		Accounts:                      accounts,
		GlobalSettingsHandler:         globalSettingsHandler,
		Marshalizer:                   &mock.MarshalizerMock{},
		EnableEpochsHandler:           enableEpochsHandler,
		ShardCoordinator:              &mock.ShardCoordinatorStub{},
		CrossChainTokenCheckerHandler: crossChainTokenChecker,
	}
	dataStore, _ := NewDCDTDataStorage(args)
	return dataStore
}

func TestNewDCDTDataStorage(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	args.Marshalizer = nil
	e, err := NewDCDTDataStorage(args)
	assert.Nil(t, e)
	assert.Equal(t, err, ErrNilMarshalizer)

	args = createMockArgsForNewDCDTDataStorage()
	args.Accounts = nil
	e, err = NewDCDTDataStorage(args)
	assert.Nil(t, e)
	assert.Equal(t, err, ErrNilAccountsAdapter)

	args = createMockArgsForNewDCDTDataStorage()
	args.ShardCoordinator = nil
	e, err = NewDCDTDataStorage(args)
	assert.Nil(t, e)
	assert.Equal(t, err, ErrNilShardCoordinator)

	args = createMockArgsForNewDCDTDataStorage()
	args.GlobalSettingsHandler = nil
	e, err = NewDCDTDataStorage(args)
	assert.Nil(t, e)
	assert.Equal(t, err, ErrNilGlobalSettingsHandler)

	args = createMockArgsForNewDCDTDataStorage()
	args.EnableEpochsHandler = nil
	e, err = NewDCDTDataStorage(args)
	assert.Nil(t, e)
	assert.Equal(t, err, ErrNilEnableEpochsHandler)

	args = createMockArgsForNewDCDTDataStorage()
	args.CrossChainTokenCheckerHandler = nil
	e, err = NewDCDTDataStorage(args)
	assert.Nil(t, e)
	assert.Equal(t, err, ErrNilCrossChainTokenChecker)

	args = createMockArgsForNewDCDTDataStorage()
	e, err = NewDCDTDataStorage(args)
	assert.Nil(t, err)
	assert.False(t, e.IsInterfaceNil())
}

func TestDcdtDataStorage_GetDCDTNFTTokenOnDestinationNoDataInSystemAcc(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	dcdtData := &dcdt.DCDigitalToken{
		TokenMetaData: &dcdt.MetaData{
			Name: []byte("test"),
		},
		Value: big.NewInt(10),
	}

	tokenIdentifier := "testTkn"
	key := baseDCDTKeyPrefix + tokenIdentifier
	nonce := uint64(10)
	dcdtDataBytes, _ := args.Marshalizer.Marshal(dcdtData)
	tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)
	_ = userAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtDataBytes)

	dcdtDataGet, _, err := e.GetDCDTNFTTokenOnDestination(userAcc, []byte(key), nonce)
	assert.Nil(t, err)
	assert.Equal(t, dcdtData, dcdtDataGet)
}

func TestDcdtDataStorage_GetDCDTNFTTokenOnDestinationTypeNonFungibleV2(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
	systemAccLoaded := false
	args.Accounts = &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			systemAccLoaded = true
			return acnt, nil
		}}
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	dcdtData := &dcdt.DCDigitalToken{
		TokenMetaData: &dcdt.MetaData{
			Name:    []byte("test"),
			Creator: []byte("creator"),
		},
		Type:  uint32(core.NonFungibleV2),
		Value: big.NewInt(10),
	}

	tokenIdentifier := "testTkn"
	key := baseDCDTKeyPrefix + tokenIdentifier
	nonce := uint64(10)
	dcdtDataBytes, _ := args.Marshalizer.Marshal(dcdtData)
	tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)
	_ = userAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtDataBytes)

	dcdtDataGet, _, err := e.GetDCDTNFTTokenOnDestination(userAcc, []byte(key), nonce)
	assert.Nil(t, err)
	assert.Equal(t, dcdtData, dcdtDataGet)
	assert.False(t, systemAccLoaded)
}

func TestDcdtDataStorage_GetDCDTNFTTokenOnDestinationGetNodeFromDbErr(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	userAcc.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, core.NewGetNodeFromDBErrWithKey(key, errors.New("error"), "")
	}

	dcdtDataGet, _, err := e.GetDCDTNFTTokenOnDestination(userAcc, []byte("key"), 1)
	assert.Nil(t, dcdtDataGet)
	assert.True(t, core.IsGetNodeFromDBError(err))
}

func TestDcdtDataStorage_GetDCDTNFTTokenOnDestinationGetDataFromSystemAcc(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	dcdtData := &dcdt.DCDigitalToken{
		Type:  uint32(core.NonFungible),
		Value: big.NewInt(10),
	}

	tokenIdentifier := "testTkn"
	key := baseDCDTKeyPrefix + tokenIdentifier
	nonce := uint64(10)
	dcdtDataBytes, _ := args.Marshalizer.Marshal(dcdtData)
	tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)
	_ = userAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtDataBytes)

	systemAcc, _ := e.getSystemAccount(defaultQueryOptions())
	metaData := &dcdt.MetaData{
		Name: []byte("test"),
	}
	dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{TokenMetaData: metaData}
	dcdtMetaDataBytes, _ := args.Marshalizer.Marshal(dcdtDataOnSystemAcc)
	_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

	dcdtDataGet, _, err := e.GetDCDTNFTTokenOnDestination(userAcc, []byte(key), nonce)
	assert.Nil(t, err)
	dcdtData.TokenMetaData = metaData
	assert.Equal(t, dcdtData, dcdtDataGet)
}

func TestDcdtDataStorage_GetDCDTNFTTokenOnDestinationWithCustomSystemAccount(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	dcdtData := &dcdt.DCDigitalToken{
		Type:  uint32(core.NonFungible),
		Value: big.NewInt(10),
	}

	tokenIdentifier := "testTkn"
	key := baseDCDTKeyPrefix + tokenIdentifier
	nonce := uint64(10)
	dcdtDataBytes, _ := args.Marshalizer.Marshal(dcdtData)
	tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)
	_ = userAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtDataBytes)

	systemAcc, _ := e.getSystemAccount(defaultQueryOptions())
	metaData := &dcdt.MetaData{
		Name: []byte("test"),
	}
	dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{TokenMetaData: metaData}
	dcdtMetaDataBytes, _ := args.Marshalizer.Marshal(dcdtDataOnSystemAcc)
	_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

	retrieveValueFromCustomAccountCalled := false
	customSystemAccount := &mock.UserAccountStub{
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &mock.DataTrieTrackerStub{
				RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
					retrieveValueFromCustomAccountCalled = true
					return dcdtMetaDataBytes, 0, nil
				},
			}
		},
	}
	dcdtDataGet, _, err := e.GetDCDTNFTTokenOnDestinationWithCustomSystemAccount(userAcc, []byte(key), nonce, customSystemAccount)
	assert.Nil(t, err)
	dcdtData.TokenMetaData = metaData
	assert.Equal(t, dcdtData, dcdtDataGet)
	assert.True(t, retrieveValueFromCustomAccountCalled)
}

func TestDcdtDataStorage_GetDCDTNFTTokenOnDestinationMarshalERR(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	dcdtData := &dcdt.DCDigitalToken{
		Value: big.NewInt(10),
		TokenMetaData: &dcdt.MetaData{
			Name: []byte("test"),
		},
	}

	tokenIdentifier := "testTkn"
	key := baseDCDTKeyPrefix + tokenIdentifier
	nonce := uint64(10)
	dcdtDataBytes, _ := args.Marshalizer.Marshal(dcdtData)
	dcdtDataBytes = append(dcdtDataBytes, dcdtDataBytes...)
	tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)
	_ = userAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtDataBytes)

	_, _, err := e.GetDCDTNFTTokenOnDestination(userAcc, []byte(key), nonce)
	assert.NotNil(t, err)

	_, err = e.GetDCDTNFTTokenOnSender(userAcc, []byte(key), nonce)
	assert.NotNil(t, err)
}

func TestDcdtDataStorage_MarshalErrorOnSystemACC(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	dcdtData := &dcdt.DCDigitalToken{
		Type:  uint32(core.NonFungible),
		Value: big.NewInt(10),
	}

	tokenIdentifier := "testTkn"
	key := baseDCDTKeyPrefix + tokenIdentifier
	nonce := uint64(10)
	dcdtDataBytes, _ := args.Marshalizer.Marshal(dcdtData)
	tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)
	_ = userAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtDataBytes)

	systemAcc, _ := e.getSystemAccount(defaultQueryOptions())
	metaData := &dcdt.MetaData{
		Name: []byte("test"),
	}
	dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{TokenMetaData: metaData}
	dcdtMetaDataBytes, _ := args.Marshalizer.Marshal(dcdtDataOnSystemAcc)
	dcdtMetaDataBytes = append(dcdtMetaDataBytes, dcdtMetaDataBytes...)
	_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

	_, _, err := e.GetDCDTNFTTokenOnDestination(userAcc, []byte(key), nonce)
	assert.NotNil(t, err)
}

func TestDCDTDataStorage_saveDataToSystemAccNotNFTOrMetaData(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	err := e.saveDCDTMetaDataToSystemAccount(nil, 0, []byte("TCK"), 0, nil, true)
	assert.Nil(t, err)

	err = e.saveDCDTMetaDataToSystemAccount(nil, 0, []byte("TCK"), 1, &dcdt.DCDigitalToken{}, true)
	assert.Nil(t, err)
}

func TestDCDTDataStorage_saveDCDTMetaDataToSystemAccountGetNodeFromDbErrForSystemAcc(t *testing.T) {
	t.Parallel()

	systemAcc := mock.NewAccountWrapMock([]byte("system acc address"))
	systemAcc.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, core.NewGetNodeFromDBErrWithKey(key, errors.New("error"), "")
	}

	args := createMockArgsForNewDCDTDataStorage()
	args.Accounts = &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAcc, nil
		},
	}
	e, _ := NewDCDTDataStorage(args)

	dcdtData := &dcdt.DCDigitalToken{
		TokenMetaData: &dcdt.MetaData{},
	}

	err := e.saveDCDTMetaDataToSystemAccount(nil, 0, []byte("TCK"), 1, dcdtData, true)
	assert.True(t, core.IsGetNodeFromDBError(err))
}

func TestDCDTDataStorage_saveDCDTMetaDataToSystemAccountGetNodeFromDbErrForUserAcc(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	args.EnableEpochsHandler = &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == FixOldTokenLiquidityFlag || flag == SendAlwaysFlag
		},
	}
	e, _ := NewDCDTDataStorage(args)

	dcdtData := &dcdt.DCDigitalToken{
		TokenMetaData: &dcdt.MetaData{},
	}

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	userAcc.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, core.NewGetNodeFromDBErrWithKey(key, errors.New("error"), "")
	}

	err := e.saveDCDTMetaDataToSystemAccount(userAcc, 0, []byte("TCK"), 1, dcdtData, true)
	assert.True(t, core.IsGetNodeFromDBError(err))
}

func TestDcdtDataStorage_SaveDCDTNFTTokenNoChangeInSystemAcc(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	dcdtData := &dcdt.DCDigitalToken{
		Type:  uint32(core.SemiFungible),
		Value: big.NewInt(10),
	}

	tokenIdentifier := "testTkn"
	key := baseDCDTKeyPrefix + tokenIdentifier
	nonce := uint64(10)
	dcdtDataBytes, _ := args.Marshalizer.Marshal(dcdtData)
	tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)
	_ = userAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtDataBytes)

	systemAcc, _ := e.getSystemAccount(defaultQueryOptions())
	metaData := &dcdt.MetaData{
		Name: []byte("test"),
	}
	dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{TokenMetaData: metaData}
	dcdtMetaDataBytes, _ := args.Marshalizer.Marshal(dcdtDataOnSystemAcc)
	_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

	newMetaData := &dcdt.MetaData{Name: []byte("newName")}
	transferDCDTData := &dcdt.DCDigitalToken{
		Type:          uint32(core.SemiFungible),
		Value:         big.NewInt(100),
		TokenMetaData: newMetaData,
	}
	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         false,
		IsReturnWithError:           false,
		KeepMetaDataOnZeroLiquidity: false,
	}
	_, err := e.SaveDCDTNFTToken([]byte("address"), userAcc, []byte(key), nonce, transferDCDTData, properties)
	assert.Nil(t, err)

	dcdtDataGet, _, err := e.GetDCDTNFTTokenOnDestination(userAcc, []byte(key), nonce)
	assert.Nil(t, err)
	dcdtData.TokenMetaData = metaData
	dcdtData.Value = big.NewInt(100)
	assert.Equal(t, dcdtData, dcdtDataGet)
}

func TestDcdtDataStorage_SaveDCDTNFTTokenAlwaysSaveTokenMetaDataEnabled(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	args.EnableEpochsHandler = &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag || flag == AlwaysSaveTokenMetaDataFlag
		},
	}
	dataStorage, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	nonce := uint64(10)

	t.Run("new token should not rewrite metadata", func(t *testing.T) {
		newToken := &dcdt.DCDigitalToken{
			Type:  uint32(core.SemiFungible),
			Value: big.NewInt(10),
		}
		tokenIdentifier := "newTkn"
		key := baseDCDTKeyPrefix + tokenIdentifier
		tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)

		_ = saveDCDTData(userAcc, newToken, tokenKey, args.Marshalizer)

		systemAcc, _ := dataStorage.getSystemAccount(defaultQueryOptions())
		metaData := &dcdt.MetaData{
			Name: []byte("test"),
		}
		dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{
			TokenMetaData: metaData,
			Reserved:      []byte{1},
		}
		dcdtMetaDataBytes, _ := args.Marshalizer.Marshal(dcdtDataOnSystemAcc)
		_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

		newMetaData := &dcdt.MetaData{Name: []byte("newName")}
		transferDCDTData := &dcdt.DCDigitalToken{
			Type:          uint32(core.SemiFungible),
			Value:         big.NewInt(100),
			TokenMetaData: newMetaData,
		}
		properties := vmcommon.NftSaveArgs{
			MustUpdateAllFields:         false,
			IsReturnWithError:           false,
			KeepMetaDataOnZeroLiquidity: false,
		}
		_, err := dataStorage.SaveDCDTNFTToken([]byte("address"), userAcc, []byte(key), nonce, transferDCDTData, properties)
		assert.Nil(t, err)

		dcdtDataGet, _, err := dataStorage.GetDCDTNFTTokenOnDestination(userAcc, []byte(key), nonce)
		assert.Nil(t, err)

		expectedDCDTData := &dcdt.DCDigitalToken{
			Type:          uint32(core.SemiFungible),
			Value:         big.NewInt(100),
			TokenMetaData: metaData,
		}
		assert.Equal(t, expectedDCDTData, dcdtDataGet)
	})
	t.Run("old token should rewrite metadata", func(t *testing.T) {
		newToken := &dcdt.DCDigitalToken{
			Value: big.NewInt(10),
		}
		tokenIdentifier := "newTkn"
		key := baseDCDTKeyPrefix + tokenIdentifier
		tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)

		_ = saveDCDTData(userAcc, newToken, tokenKey, args.Marshalizer)

		systemAcc, _ := dataStorage.getSystemAccount(defaultQueryOptions())
		metaData := &dcdt.MetaData{
			Name: []byte("test"),
		}
		dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{
			TokenMetaData: metaData,
		}
		dcdtMetaDataBytes, _ := args.Marshalizer.Marshal(dcdtDataOnSystemAcc)
		_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

		newMetaData := &dcdt.MetaData{Name: []byte("newName")}
		transferDCDTData := &dcdt.DCDigitalToken{Value: big.NewInt(100), TokenMetaData: newMetaData}
		dcdtDataGet := setAndGetStoredToken(t, dataStorage, userAcc, []byte(key), nonce, transferDCDTData)

		expectedDCDTData := &dcdt.DCDigitalToken{
			Value:         big.NewInt(100),
			TokenMetaData: newMetaData,
		}
		assert.Equal(t, expectedDCDTData, dcdtDataGet)
	})
	t.Run("old token should not rewrite metadata if the flags are not set", func(t *testing.T) {
		localArgs := createMockArgsForNewDCDTDataStorage()
		localEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag || flag == AlwaysSaveTokenMetaDataFlag
			},
		}
		localArgs.EnableEpochsHandler = localEpochsHandler
		localDataStorage, _ := NewDCDTDataStorage(localArgs)

		newToken := &dcdt.DCDigitalToken{
			Type:  uint32(core.SemiFungible),
			Value: big.NewInt(10),
		}
		tokenIdentifier := "newTkn"
		key := baseDCDTKeyPrefix + tokenIdentifier
		tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)

		_ = saveDCDTData(userAcc, newToken, tokenKey, localArgs.Marshalizer)

		systemAcc, _ := localDataStorage.getSystemAccount(defaultQueryOptions())
		metaData := &dcdt.MetaData{
			Name: []byte("test"),
		}
		dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{
			TokenMetaData: metaData,
		}
		dcdtMetaDataBytes, _ := localArgs.Marshalizer.Marshal(dcdtDataOnSystemAcc)
		_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

		newMetaData := &dcdt.MetaData{Name: []byte("newName")}
		transferDCDTData := &dcdt.DCDigitalToken{
			Type:          uint32(core.SemiFungible),
			Value:         big.NewInt(100),
			TokenMetaData: newMetaData}
		expectedDCDTData := &dcdt.DCDigitalToken{
			Type:          uint32(core.SemiFungible),
			Value:         big.NewInt(100),
			TokenMetaData: metaData,
		}

		localEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
			return flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag
		}

		dcdtDataGet := setAndGetStoredToken(t, localDataStorage, userAcc, []byte(key), nonce, transferDCDTData)
		assert.Equal(t, expectedDCDTData, dcdtDataGet)

		localEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
			return flag == SaveToSystemAccountFlag || flag == AlwaysSaveTokenMetaDataFlag
		}

		dcdtDataGet = setAndGetStoredToken(t, localDataStorage, userAcc, []byte(key), nonce, transferDCDTData)
		assert.Equal(t, expectedDCDTData, dcdtDataGet)
	})
}

func setAndGetStoredToken(
	tb testing.TB,
	dcdtDataStorage *dcdtDataStorage,
	userAcc vmcommon.UserAccountHandler,
	key []byte,
	nonce uint64,
	transferDCDTData *dcdt.DCDigitalToken,
) *dcdt.DCDigitalToken {
	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         false,
		IsReturnWithError:           false,
		KeepMetaDataOnZeroLiquidity: false,
	}
	_, err := dcdtDataStorage.SaveDCDTNFTToken([]byte("address"), userAcc, key, nonce, transferDCDTData, properties)
	assert.Nil(tb, err)

	dcdtDataGet, _, err := dcdtDataStorage.GetDCDTNFTTokenOnDestination(userAcc, key, nonce)
	assert.Nil(tb, err)

	return dcdtDataGet
}

func TestDcdtDataStorage_SaveDCDTNFTTokenWhenQuantityZero(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	nonce := uint64(10)
	dcdtData := &dcdt.DCDigitalToken{
		Type:  uint32(core.SemiFungible),
		Value: big.NewInt(10),
		TokenMetaData: &dcdt.MetaData{
			Name:  []byte("test"),
			Nonce: nonce,
		},
	}

	tokenIdentifier := "testTkn"
	key := baseDCDTKeyPrefix + tokenIdentifier
	dcdtDataBytes, _ := args.Marshalizer.Marshal(dcdtData)
	tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)
	_ = userAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtDataBytes)

	dcdtData.Value = big.NewInt(0)
	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         false,
		IsReturnWithError:           false,
		KeepMetaDataOnZeroLiquidity: false,
	}
	_, err := e.SaveDCDTNFTToken([]byte("address"), userAcc, []byte(key), nonce, dcdtData, properties)
	assert.Nil(t, err)

	val, _, err := userAcc.AccountDataHandler().RetrieveValue(tokenKey)
	assert.Nil(t, val)
	assert.Nil(t, err)

	dcdtMetaData, err := e.getDCDTMetaDataFromSystemAccount(tokenKey, defaultQueryOptions())
	assert.Nil(t, err)
	assert.Equal(t, dcdtData.TokenMetaData, dcdtMetaData)
}

func TestDcdtDataStorage_SaveDCDTNFTToken(t *testing.T) {
	t.Parallel()

	t.Run("migrate metadata from system account to user account for NonFungibleV2", func(t *testing.T) {
		t.Parallel()

		tokenIdentifier := "newTkn"
		nonce := uint64(10)
		key := baseDCDTKeyPrefix + tokenIdentifier
		tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)

		args := createMockArgsForNewDCDTDataStorage()
		args.GlobalSettingsHandler = &mock.GlobalSettingsHandlerStub{
			GetTokenTypeCalled: func(dcdtTokenKey []byte) (uint32, error) {
				return uint32(core.NonFungibleV2), nil
			},
		}
		args.EnableEpochsHandler = &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag || flag == DynamicDcdtFlag
			},
		}
		dataStorage, _ := NewDCDTDataStorage(args)
		userAcc := mock.NewAccountWrapMock([]byte("addr"))
		nftToken := &dcdt.DCDigitalToken{
			Value: big.NewInt(10),
		}
		_ = saveDCDTData(userAcc, nftToken, tokenKey, args.Marshalizer)

		systemAcc, _ := dataStorage.getSystemAccount(defaultQueryOptions())
		metaData := &dcdt.MetaData{
			Name: []byte("test"),
		}
		dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{
			TokenMetaData: metaData,
			Reserved:      []byte{1},
		}
		dcdtMetaDataBytes, _ := args.Marshalizer.Marshal(dcdtDataOnSystemAcc)
		_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

		nftToken.Type = uint32(core.NonFungible)
		nftToken.TokenMetaData = metaData

		properties := vmcommon.NftSaveArgs{
			MustUpdateAllFields:         false,
			IsReturnWithError:           false,
			KeepMetaDataOnZeroLiquidity: false,
		}
		_, err := dataStorage.SaveDCDTNFTToken([]byte("address"), userAcc, []byte(key), nonce, nftToken, properties)
		assert.Nil(t, err)

		// metadata has been removed from the system account
		val, _, _ := systemAcc.AccountDataHandler().RetrieveValue(tokenKey)
		assert.Nil(t, val)

		nftToken.Type = uint32(core.NonFungibleV2)
		nftTokenBytes, _ := args.Marshalizer.Marshal(nftToken)
		// metadata has been added to the user account
		val, _, err = userAcc.RetrieveValue(tokenKey)
		assert.Nil(t, err)
		assert.Equal(t, nftTokenBytes, val)
	})
}

func TestDcdtDataStorage_WasAlreadySentToDestinationShard(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	shardCoordinator := &mock.ShardCoordinatorStub{}
	args.ShardCoordinator = shardCoordinator
	e, _ := NewDCDTDataStorage(args)

	tickerID := []byte("ticker")
	dstAddress := []byte("dstAddress")
	val, err := e.WasAlreadySentToDestinationShardAndUpdateState(tickerID, 0, dstAddress)
	assert.True(t, val)
	assert.Nil(t, err)

	val, err = e.WasAlreadySentToDestinationShardAndUpdateState(tickerID, 1, dstAddress)
	assert.True(t, val)
	assert.Nil(t, err)

	enableEpochsHandler, _ := args.EnableEpochsHandler.(*mock.EnableEpochsHandlerStub)
	enableEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		return flag == SaveToSystemAccountFlag
	}
	shardCoordinator.ComputeIdCalled = func(_ []byte) uint32 {
		return core.MetachainShardId
	}
	val, err = e.WasAlreadySentToDestinationShardAndUpdateState(tickerID, 1, dstAddress)
	assert.True(t, val)
	assert.Nil(t, err)

	enableEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		return flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag
	}

	shardCoordinator.ComputeIdCalled = func(_ []byte) uint32 {
		return 1
	}
	shardCoordinator.NumberOfShardsCalled = func() uint32 {
		return 5
	}
	val, err = e.WasAlreadySentToDestinationShardAndUpdateState(tickerID, 1, dstAddress)
	assert.False(t, val)
	assert.Nil(t, err)

	systemAcc, _ := e.getSystemAccount(defaultQueryOptions())
	metaData := &dcdt.MetaData{
		Name: []byte("test"),
	}
	dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{TokenMetaData: metaData}
	dcdtMetaDataBytes, _ := args.Marshalizer.Marshal(dcdtDataOnSystemAcc)
	key := baseDCDTKeyPrefix + string(tickerID)
	tokenKey := append([]byte(key), big.NewInt(1).Bytes()...)
	_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

	val, err = e.WasAlreadySentToDestinationShardAndUpdateState(tickerID, 1, dstAddress)
	assert.False(t, val)
	assert.Nil(t, err)

	val, err = e.WasAlreadySentToDestinationShardAndUpdateState(tickerID, 1, dstAddress)
	assert.False(t, val)
	assert.Nil(t, err)

	enableEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		return flag == SaveToSystemAccountFlag
	}
	val, err = e.WasAlreadySentToDestinationShardAndUpdateState(tickerID, 1, dstAddress)
	assert.False(t, val)
	assert.Nil(t, err)

	shardCoordinator.NumberOfShardsCalled = func() uint32 {
		return 10
	}
	val, err = e.WasAlreadySentToDestinationShardAndUpdateState(tickerID, 1, dstAddress)
	assert.True(t, val)
	assert.Nil(t, err)
}

func TestDcdtDataStorage_SaveNFTMetaData(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	shardCoordinator := &mock.ShardCoordinatorStub{}
	args.ShardCoordinator = shardCoordinator
	e, _ := NewDCDTDataStorage(args)

	enableEpochsHandler, _ := args.EnableEpochsHandler.(*mock.EnableEpochsHandlerStub)
	enableEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		return flag == SendAlwaysFlag
	}
	err := e.SaveNFTMetaData(nil)
	assert.Nil(t, err)

	enableEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		return flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag
	}
	err = e.SaveNFTMetaData(nil)
	assert.Nil(t, err)

	enableEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		return flag == SaveToSystemAccountFlag
	}
	err = e.SaveNFTMetaData(nil)
	assert.Equal(t, err, ErrNilTransactionHandler)

	scr := &smartContractResult.SmartContractResult{
		SndAddr: []byte("address1"),
		RcvAddr: []byte("address2"),
	}

	err = e.SaveNFTMetaData(scr)
	assert.Nil(t, err)

	shardCoordinator.ComputeIdCalled = func(address []byte) uint32 {
		if bytes.Equal(address, scr.SndAddr) {
			return 0
		}
		if bytes.Equal(address, scr.RcvAddr) {
			return 1
		}
		return 2
	}
	shardCoordinator.NumberOfShardsCalled = func() uint32 {
		return 3
	}
	shardCoordinator.SelfIdCalled = func() uint32 {
		return 1
	}

	err = e.SaveNFTMetaData(scr)
	assert.Nil(t, err)

	scr.Data = []byte("function")
	err = e.SaveNFTMetaData(scr)
	assert.Nil(t, err)

	scr.Data = []byte("function@01@02@03@04")
	err = e.SaveNFTMetaData(scr)
	assert.Nil(t, err)

	scr.Data = []byte(core.BuiltInFunctionDCDTNFTTransfer + "@01@02@03@04")
	err = e.SaveNFTMetaData(scr)
	assert.NotNil(t, err)

	scr.Data = []byte(core.BuiltInFunctionDCDTNFTTransfer + "@01@02@03@00")
	err = e.SaveNFTMetaData(scr)
	assert.Nil(t, err)

	tickerID := []byte("TCK")
	dcdtData := &dcdt.DCDigitalToken{
		Value: big.NewInt(10),
		TokenMetaData: &dcdt.MetaData{
			Name: []byte("test"),
		},
	}
	dcdtMarshalled, _ := args.Marshalizer.Marshal(dcdtData)
	scr.Data = []byte(core.BuiltInFunctionDCDTNFTTransfer + "@" + hex.EncodeToString(tickerID) + "@01@01@" + hex.EncodeToString(dcdtMarshalled))
	err = e.SaveNFTMetaData(scr)
	assert.Nil(t, err)

	key := baseDCDTKeyPrefix + string(tickerID)
	tokenKey := append([]byte(key), big.NewInt(1).Bytes()...)
	dcdtGetData, _, _ := e.getDCDTDigitalTokenDataFromSystemAccount(tokenKey, defaultQueryOptions())

	assert.Equal(t, dcdtData.TokenMetaData, dcdtGetData.TokenMetaData)
}

func TestDcdtDataStorage_getDCDTDigitalTokenDataFromSystemAccountGetNodeFromDbErr(t *testing.T) {
	t.Parallel()

	systemAcc := mock.NewAccountWrapMock([]byte("system acc address"))
	systemAcc.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, core.NewGetNodeFromDBErrWithKey(key, errors.New("error"), "")
	}

	args := createMockArgsForNewDCDTDataStorage()
	args.Accounts = &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAcc, nil
		},
	}
	e, _ := NewDCDTDataStorage(args)

	dcdtDataGet, _, err := e.getDCDTDigitalTokenDataFromSystemAccount([]byte("tokenKey"), defaultQueryOptions())
	assert.Nil(t, dcdtDataGet)
	assert.True(t, core.IsGetNodeFromDBError(err))
}

func TestDcdtDataStorage_SaveNFTMetaDataWithMultiTransfer(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	shardCoordinator := &mock.ShardCoordinatorStub{}
	args.ShardCoordinator = shardCoordinator
	args.EnableEpochsHandler = &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == SaveToSystemAccountFlag
		},
	}
	e, _ := NewDCDTDataStorage(args)

	scr := &smartContractResult.SmartContractResult{
		SndAddr: []byte("address1"),
		RcvAddr: []byte("address2"),
	}

	shardCoordinator.ComputeIdCalled = func(address []byte) uint32 {
		if bytes.Equal(address, scr.SndAddr) {
			return 0
		}
		if bytes.Equal(address, scr.RcvAddr) {
			return 1
		}
		return 2
	}
	shardCoordinator.NumberOfShardsCalled = func() uint32 {
		return 3
	}
	shardCoordinator.SelfIdCalled = func() uint32 {
		return 1
	}

	tickerID := []byte("TCK")
	dcdtData := &dcdt.DCDigitalToken{
		Value: big.NewInt(10),
		TokenMetaData: &dcdt.MetaData{
			Name: []byte("test"),
		},
	}
	dcdtMarshalled, _ := args.Marshalizer.Marshal(dcdtData)
	scr.Data = []byte(core.BuiltInFunctionMultiDCDTNFTTransfer + "@00@" + hex.EncodeToString(tickerID) + "@01@01@" + hex.EncodeToString(dcdtMarshalled))
	err := e.SaveNFTMetaData(scr)
	assert.True(t, errors.Is(err, ErrInvalidArguments))

	scr.Data = []byte(core.BuiltInFunctionMultiDCDTNFTTransfer + "@02@" + hex.EncodeToString(tickerID) + "@01@01@" + hex.EncodeToString(dcdtMarshalled))
	err = e.SaveNFTMetaData(scr)
	assert.True(t, errors.Is(err, ErrInvalidArguments))

	scr.Data = []byte(core.BuiltInFunctionMultiDCDTNFTTransfer + "@02@" + hex.EncodeToString(tickerID) + "@02@10@" +
		hex.EncodeToString(tickerID) + "@01@" + hex.EncodeToString(dcdtMarshalled))
	err = e.SaveNFTMetaData(scr)
	assert.Nil(t, err)

	key := baseDCDTKeyPrefix + string(tickerID)
	tokenKey := append([]byte(key), big.NewInt(1).Bytes()...)
	dcdtGetData, _, _ := e.getDCDTDigitalTokenDataFromSystemAccount(tokenKey, defaultQueryOptions())

	assert.Equal(t, dcdtData.TokenMetaData, dcdtGetData.TokenMetaData)

	otherTokenKey := append([]byte(key), big.NewInt(2).Bytes()...)
	dcdtGetData, _, err = e.getDCDTDigitalTokenDataFromSystemAccount(otherTokenKey, defaultQueryOptions())
	assert.Nil(t, dcdtGetData)
	assert.Nil(t, err)
}

func TestDcdtDataStorage_checkCollectionFrozen(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	shardCoordinator := &mock.ShardCoordinatorStub{}
	args.ShardCoordinator = shardCoordinator
	e, _ := NewDCDTDataStorage(args)

	enableEpochsHandler, _ := args.EnableEpochsHandler.(*mock.EnableEpochsHandlerStub)
	enableEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		return false
	}

	acnt, _ := e.accounts.LoadAccount([]byte("address1"))
	userAcc := acnt.(vmcommon.UserAccountHandler)

	tickerID := []byte("TOKEN-ABCDEF")
	dcdtTokenKey := append(e.keyPrefix, tickerID...)
	err := e.checkCollectionIsFrozenForAccount(userAcc, dcdtTokenKey, 1, false)
	assert.Nil(t, err)

	enableEpochsHandler.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
		return flag == CheckFrozenCollectionFlag
	}
	err = e.checkCollectionIsFrozenForAccount(userAcc, dcdtTokenKey, 0, false)
	assert.Nil(t, err)

	err = e.checkCollectionIsFrozenForAccount(userAcc, dcdtTokenKey, 1, true)
	assert.Nil(t, err)

	err = e.checkCollectionIsFrozenForAccount(userAcc, dcdtTokenKey, 1, false)
	assert.Nil(t, err)

	tokenData, _ := getDCDTDataFromKey(userAcc, dcdtTokenKey, e.marshaller)

	dcdtUserMetadata := DCDTUserMetadataFromBytes(tokenData.Properties)
	dcdtUserMetadata.Frozen = false
	tokenData.Properties = dcdtUserMetadata.ToBytes()
	_ = saveDCDTData(userAcc, tokenData, dcdtTokenKey, e.marshaller)

	err = e.checkCollectionIsFrozenForAccount(userAcc, dcdtTokenKey, 1, false)
	assert.Nil(t, err)

	dcdtUserMetadata.Frozen = true
	tokenData.Properties = dcdtUserMetadata.ToBytes()
	_ = saveDCDTData(userAcc, tokenData, dcdtTokenKey, e.marshaller)

	err = e.checkCollectionIsFrozenForAccount(userAcc, dcdtTokenKey, 1, false)
	assert.Equal(t, err, ErrDCDTIsFrozenForAccount)
}

func TestGetDcdtDataFromKey(t *testing.T) {
	t.Parallel()

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	userAcc.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, core.NewGetNodeFromDBErrWithKey(key, errors.New("error"), "")
	}
	tokenData, err := getDCDTDataFromKey(userAcc, []byte("dcdtTokenKey"), &mock.MarshalizerMock{})
	assert.Nil(t, tokenData)
	assert.True(t, core.IsGetNodeFromDBError(err))
}

func TestDcdtDataStorage_checkCollectionFrozenGetNodeFromDbErr(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	args.EnableEpochsHandler = &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == CheckFrozenCollectionFlag
		},
	}
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	userAcc.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, core.NewGetNodeFromDBErrWithKey(key, errors.New("error"), "")
	}

	err := e.checkCollectionIsFrozenForAccount(userAcc, []byte("key"), 1, false)
	assert.True(t, core.IsGetNodeFromDBError(err))
}

func TestDcdtDataStorage_AddToLiquiditySystemAcc(t *testing.T) {
	t.Parallel()

	args := createMockArgsForNewDCDTDataStorage()
	e, _ := NewDCDTDataStorage(args)

	tokenKey := append(e.keyPrefix, []byte("TOKEN-ababab")...)
	nonce := uint64(10)
	err := e.AddToLiquiditySystemAcc(tokenKey, 3, nonce, big.NewInt(10), false)
	assert.Equal(t, err, ErrNilDCDTData)

	systemAcc, _ := e.getSystemAccount(defaultQueryOptions())
	dcdtData := &dcdt.DCDigitalToken{
		Type:  uint32(core.SemiFungible),
		Value: big.NewInt(0),
	}
	marshalledData, _ := e.marshaller.Marshal(dcdtData)

	dcdtNFTTokenKey := computeDCDTNFTTokenKey(tokenKey, nonce)
	_ = systemAcc.AccountDataHandler().SaveKeyValue(dcdtNFTTokenKey, marshalledData)

	err = e.AddToLiquiditySystemAcc(tokenKey, 3, nonce, big.NewInt(10), false)
	assert.Nil(t, err)

	dcdtData = &dcdt.DCDigitalToken{
		Type:     uint32(core.SemiFungible),
		Value:    big.NewInt(10),
		Reserved: []byte{1},
	}
	marshalledData, _ = e.marshaller.Marshal(dcdtData)

	_ = systemAcc.AccountDataHandler().SaveKeyValue(dcdtNFTTokenKey, marshalledData)
	err = e.AddToLiquiditySystemAcc(tokenKey, 3, nonce, big.NewInt(10), false)
	assert.Nil(t, err)

	dcdtData, _, _ = e.getDCDTDigitalTokenDataFromSystemAccount(dcdtNFTTokenKey, defaultQueryOptions())
	assert.Equal(t, dcdtData.Value, big.NewInt(20))

	err = e.AddToLiquiditySystemAcc(tokenKey, 3, nonce, big.NewInt(-20), false)
	assert.Nil(t, err)

	dcdtData, _, _ = e.getDCDTDigitalTokenDataFromSystemAccount(dcdtNFTTokenKey, defaultQueryOptions())
	assert.Nil(t, dcdtData)
}

func TestDcdtDataStorage_ShouldSaveMetadataInSystemAccount(t *testing.T) {
	t.Parallel()

	t.Run("returns false if SaveToSystemAccountFlag flag disabled", func(t *testing.T) {
		t.Parallel()

		args := createMockArgsForNewDCDTDataStorage()
		args.EnableEpochsHandler = &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return false
			},
		}
		e, _ := NewDCDTDataStorage(args)

		assert.False(t, e.shouldSaveMetadataInSystemAccount(uint32(core.NonFungibleV2)))
	})

	t.Run("returns true if dynamic token type", func(t *testing.T) {
		t.Parallel()

		args := createMockArgsForNewDCDTDataStorage()
		args.EnableEpochsHandler = &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return flag == SaveToSystemAccountFlag
			},
		}
		e, _ := NewDCDTDataStorage(args)

		assert.False(t, e.shouldSaveMetadataInSystemAccount(uint32(core.DynamicNFT)))
		assert.True(t, e.shouldSaveMetadataInSystemAccount(uint32(core.DynamicSFT)))
		assert.True(t, e.shouldSaveMetadataInSystemAccount(uint32(core.DynamicMeta)))
	})

	t.Run("returns false if NonFungibleV2", func(t *testing.T) {
		t.Parallel()

		args := createMockArgsForNewDCDTDataStorage()
		args.EnableEpochsHandler = &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return flag == SaveToSystemAccountFlag
			},
		}
		e, _ := NewDCDTDataStorage(args)

		assert.False(t, e.shouldSaveMetadataInSystemAccount(uint32(core.NonFungibleV2)))
		assert.True(t, e.shouldSaveMetadataInSystemAccount(uint32(core.NonFungible)))
	})
}

func TestDcdtDataStorage_GetMetaDataFromSystemAccount(t *testing.T) {
	t.Parallel()

	key := []byte("tokenKey")
	nonce := uint64(10)
	keyNonce := append(key, big.NewInt(int64(nonce)).Bytes()...)

	args := createMockArgsForNewDCDTDataStorage()
	acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)

	args.Accounts = &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		}}
	e, _ := NewDCDTDataStorage(args)

	metaData := &dcdt.MetaData{
		Name: []byte("test"),
	}
	dcdtData := &dcdt.DCDigitalToken{
		TokenMetaData: metaData,
	}
	dcdtDataBytes, _ := e.marshaller.Marshal(dcdtData)
	_ = acnt.SaveKeyValue(keyNonce, dcdtDataBytes)

	retrievedMetaData, err := e.GetMetaDataFromSystemAccount(key, nonce)
	assert.Nil(t, err)
	assert.Equal(t, dcdtData, retrievedMetaData)
}

func TestDcdtDataStorage_SaveMetaDataToSystemAccount(t *testing.T) {
	t.Parallel()

	key := []byte("tokenKey")
	nonce := uint64(10)
	keyNonce := append(key, big.NewInt(int64(nonce)).Bytes()...)

	args := createMockArgsForNewDCDTDataStorage()
	acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
	args.Accounts = &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		}}
	e, _ := NewDCDTDataStorage(args)

	metaData := &dcdt.MetaData{
		Name: []byte("test"),
	}
	dcdtData := &dcdt.DCDigitalToken{
		TokenMetaData: metaData,
	}

	err := e.SaveMetaDataToSystemAccount(key, nonce, dcdtData)
	assert.Nil(t, err)

	retrievedVal, _, err := acnt.AccountDataHandler().RetrieveValue(keyNonce)
	assert.Nil(t, err)
	dcdtDataBytes, _ := e.marshaller.Marshal(dcdtData)
	assert.Equal(t, dcdtDataBytes, retrievedVal)
}

func TestDcdtDataStorage_SaveDCDTNFTToken_migrateTypeAndMetadata(t *testing.T) {
	t.Parallel()

	t.Run("migrate token type for NonFungibleV2", func(t *testing.T) {
		t.Parallel()

		saveDCDTNFTTokenMigrateTypeAndMetadata(t, core.NonFungibleV2)
	})
	t.Run("migrate metadata for SemiFungible", func(t *testing.T) {
		t.Parallel()

		saveDCDTNFTTokenMigrateTypeAndMetadata(t, core.SemiFungible)
	})
	t.Run("migrate metadata for MetaFungible", func(t *testing.T) {
		t.Parallel()

		saveDCDTNFTTokenMigrateTypeAndMetadata(t, core.MetaFungible)
	})
	t.Run("migrate metadata for DynamicNFT", func(t *testing.T) {
		t.Parallel()

		saveDCDTNFTTokenMigrateTypeAndMetadata(t, core.DynamicNFT)
	})
	t.Run("migrate metadata for DynamicMeta", func(t *testing.T) {
		t.Parallel()

		saveDCDTNFTTokenMigrateTypeAndMetadata(t, core.DynamicMeta)
	})
	t.Run("migrate metadata for DynamicSFT", func(t *testing.T) {
		t.Parallel()

		saveDCDTNFTTokenMigrateTypeAndMetadata(t, core.DynamicSFT)
	})

}

func saveDCDTNFTTokenMigrateTypeAndMetadata(t *testing.T, tokenType core.DCDTType) {
	args := createMockArgsForNewDCDTDataStorage()
	args.EnableEpochsHandler = &mock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == SaveToSystemAccountFlag || flag == SendAlwaysFlag || flag == DynamicDcdtFlag
		},
	}
	args.GlobalSettingsHandler = &mock.GlobalSettingsHandlerStub{
		GetTokenTypeCalled: func(dcdtTokenKey []byte) (uint32, error) {
			return uint32(tokenType), nil
		},
	}
	e, _ := NewDCDTDataStorage(args)

	userAcc := mock.NewAccountWrapMock([]byte("addr"))
	dcdtData := &dcdt.DCDigitalToken{
		Value: big.NewInt(10),
		Type:  uint32(core.NonFungible),
	}

	tokenIdentifier := "testTkn"
	key := baseDCDTKeyPrefix + tokenIdentifier
	nonce := uint64(10)
	dcdtDataBytes, _ := args.Marshalizer.Marshal(dcdtData)
	tokenKey := append([]byte(key), big.NewInt(int64(nonce)).Bytes()...)
	_ = userAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtDataBytes)

	systemAcc, _ := e.getSystemAccount(defaultQueryOptions())
	metaData := &dcdt.MetaData{
		Name: []byte("test"),
	}
	dcdtDataOnSystemAcc := &dcdt.DCDigitalToken{TokenMetaData: metaData}
	dcdtMetaDataBytes, _ := args.Marshalizer.Marshal(dcdtDataOnSystemAcc)
	_ = systemAcc.AccountDataHandler().SaveKeyValue(tokenKey, dcdtMetaDataBytes)

	retrievedDcdtData, _, err := e.GetDCDTNFTTokenOnDestination(userAcc, []byte(key), nonce)
	assert.Nil(t, err)
	assert.Equal(t, uint32(core.NonFungible), retrievedDcdtData.Type)

	dcdtData.TokenMetaData = metaData
	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         false,
		IsReturnWithError:           false,
		KeepMetaDataOnZeroLiquidity: false,
	}
	_, err = e.SaveDCDTNFTToken([]byte("address"), userAcc, []byte(key), nonce, dcdtData, properties)
	assert.Nil(t, err)

	retrievedDcdtData, _, err = e.GetDCDTNFTTokenOnDestination(userAcc, []byte(key), nonce)
	assert.Nil(t, err)
	assert.Equal(t, uint32(tokenType), retrievedDcdtData.Type)

	if tokenType == core.NonFungibleV2 {
		retrievedMetaData, err := e.GetMetaDataFromSystemAccount([]byte(key), nonce)
		assert.Nil(t, err)
		assert.Nil(t, retrievedMetaData)
	} else {
		retrievedMetaData, err := e.GetMetaDataFromSystemAccount([]byte(key), nonce)
		assert.Nil(t, err)
		assert.Equal(t, &dcdt.DCDigitalToken{TokenMetaData: metaData}, retrievedMetaData)
	}
}
