package mock

import (
	"math/big"

	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
)

// AccountWrapMock -
type AccountWrapMock struct {
	MockValue    int
	nonce        uint64
	code         []byte
	codeMetadata []byte
	codeHash     []byte
	rootHash     []byte
	address      []byte
	storage      map[string][]byte

	SetNonceWithJournalCalled    func(nonce uint64) error    `json:"-"`
	SetCodeHashWithJournalCalled func(codeHash []byte) error `json:"-"`
	SetCodeWithJournalCalled     func(codeHash []byte) error `json:"-"`
	RetrieveValueCalled          func(key []byte) ([]byte, uint32, error)
}

// ClearDataCaches -
func (awm *AccountWrapMock) ClearDataCaches() {
}

// DirtyData -
func (awm *AccountWrapMock) DirtyData() map[string][]byte {
	return awm.storage
}

// RetrieveValue -
func (awm *AccountWrapMock) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if awm.RetrieveValueCalled != nil {
		return awm.RetrieveValueCalled(key)
	}

	return awm.storage[string(key)], 0, nil
}

// SaveKeyValue -
func (awm *AccountWrapMock) SaveKeyValue(key []byte, value []byte) error {
	awm.storage[string(key)] = value
	return nil
}

// MigrateDataTrieLeaves -
func (awm *AccountWrapMock) MigrateDataTrieLeaves(_ vmcommon.ArgsMigrateDataTrieLeaves) error {
	return nil
}

// NewAccountWrapMock -
func NewAccountWrapMock(adr []byte) *AccountWrapMock {
	return &AccountWrapMock{
		address: adr,
		storage: make(map[string][]byte),
	}
}

// HasNewCode -
func (awm *AccountWrapMock) HasNewCode() bool {
	return false
}

// SetUserName -
func (awm *AccountWrapMock) SetUserName(_ []byte) {
}

// GetUserName -
func (awm *AccountWrapMock) GetUserName() []byte {
	return nil
}

// AddToBalance -
func (awm *AccountWrapMock) AddToBalance(_ *big.Int) error {
	return nil
}

// SubFromBalance -
func (awm *AccountWrapMock) SubFromBalance(_ *big.Int) error {
	return nil
}

// GetBalance -
func (awm *AccountWrapMock) GetBalance() *big.Int {
	return nil
}

// ClaimDeveloperRewards -
func (awm *AccountWrapMock) ClaimDeveloperRewards([]byte) (*big.Int, error) {
	return nil, nil
}

// AddToDeveloperReward -
func (awm *AccountWrapMock) AddToDeveloperReward(_ *big.Int) {

}

// GetDeveloperReward -
func (awm *AccountWrapMock) GetDeveloperReward() *big.Int {
	return nil
}

// ChangeOwnerAddress -
func (awm *AccountWrapMock) ChangeOwnerAddress([]byte, []byte) error {
	return nil
}

// SetOwnerAddress -
func (awm *AccountWrapMock) SetOwnerAddress([]byte) {

}

// GetOwnerAddress -
func (awm *AccountWrapMock) GetOwnerAddress() []byte {
	return nil
}

// GetCodeHash -
func (awm *AccountWrapMock) GetCodeHash() []byte {
	return awm.codeHash
}

// SetCodeHash -
func (awm *AccountWrapMock) SetCodeHash(codeHash []byte) {
	awm.codeHash = codeHash
}

// SetCode -
func (awm *AccountWrapMock) SetCode(code []byte) {
	awm.code = code
}

// SetCodeMetadata -
func (awm *AccountWrapMock) SetCodeMetadata(codeMetadata []byte) {
	awm.codeMetadata = codeMetadata
}

// GetCodeMetadata -
func (awm *AccountWrapMock) GetCodeMetadata() []byte {
	return awm.codeMetadata
}

// GetRootHash -
func (awm *AccountWrapMock) GetRootHash() []byte {
	return awm.rootHash
}

// SetRootHash -
func (awm *AccountWrapMock) SetRootHash(rootHash []byte) {
	awm.rootHash = rootHash
}

// AddressBytes -
func (awm *AccountWrapMock) AddressBytes() []byte {
	return awm.address
}

// AccountDataHandler -
func (awm *AccountWrapMock) AccountDataHandler() vmcommon.AccountDataHandler {
	return awm
}

// IncreaseNonce -
func (awm *AccountWrapMock) IncreaseNonce(val uint64) {
	awm.nonce = awm.nonce + val
}

// GetNonce -
func (awm *AccountWrapMock) GetNonce() uint64 {
	return awm.nonce
}

// IsInterfaceNil -
func (awm *AccountWrapMock) IsInterfaceNil() bool {
	return awm == nil
}
