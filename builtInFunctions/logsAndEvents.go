package builtInFunctions

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"

	vmcommon "github.com/TerraDharitri/drt-go-chain-vm-common"
)

const (
	dcdtIdentifierSeparator  = "-"
	dcdtRandomSequenceLength = 6
)

// TopicTokenData groups data that will end up in Topics section of LogEntry
type TopicTokenData struct {
	TokenID []byte
	Nonce   uint64
	Value   *big.Int
}

func addDCDTEntryForTransferInVMOutput(
	vmInput *vmcommon.ContractCallInput,
	vmOutput *vmcommon.VMOutput,
	identifier []byte,
	destination []byte,
	topicTokenData []*TopicTokenData,
) {

	topicTokenBytes := make([][]byte, 0)
	for _, tokenData := range topicTokenData {
		nonceBig := big.NewInt(0).SetUint64(tokenData.Nonce)
		topicTokenBytes = append(topicTokenBytes, tokenData.TokenID, nonceBig.Bytes(), tokenData.Value.Bytes())
	}
	topicTokenBytes = append(topicTokenBytes, destination)

	logEntry := &vmcommon.LogEntry{
		Identifier: identifier,
		Address:    vmInput.CallerAddr,
		Topics:     topicTokenBytes,
		Data:       vmcommon.FormatLogDataForCall("", vmInput.Function, vmInput.Arguments),
	}

	if vmOutput.Logs == nil {
		vmOutput.Logs = make([]*vmcommon.LogEntry, 0, 1)
	}

	vmOutput.Logs = append(vmOutput.Logs, logEntry)
}

func addDCDTEntryInVMOutput(vmOutput *vmcommon.VMOutput, identifier []byte, tokenID []byte, nonce uint64, value *big.Int, args ...[]byte) {
	entry := newEntryForDCDT(identifier, tokenID, nonce, value, args...)

	if vmOutput.Logs == nil {
		vmOutput.Logs = make([]*vmcommon.LogEntry, 0, 1)
	}

	vmOutput.Logs = append(vmOutput.Logs, entry)
}

func newEntryForDCDT(identifier, tokenID []byte, nonce uint64, value *big.Int, args ...[]byte) *vmcommon.LogEntry {
	nonceBig := big.NewInt(0).SetUint64(nonce)

	logEntry := &vmcommon.LogEntry{
		Identifier: identifier,
		Topics:     [][]byte{tokenID, nonceBig.Bytes(), value.Bytes()},
	}

	if len(args) > 0 {
		logEntry.Address = args[0]
	}

	if len(args) > 1 {
		logEntry.Topics = append(logEntry.Topics, args[1:]...)
	}

	return logEntry
}

func extractTokenIdentifierAndNonceDCDTWipe(args []byte) ([]byte, uint64) {
	argsSplit := bytes.Split(args, []byte(dcdtIdentifierSeparator))
	if len(argsSplit) < 2 {
		return args, 0
	}

	if len(argsSplit[1]) <= dcdtRandomSequenceLength {
		return args, 0
	}

	identifier := []byte(fmt.Sprintf("%s-%s", argsSplit[0], argsSplit[1][:dcdtRandomSequenceLength]))
	nonce := big.NewInt(0).SetBytes(argsSplit[1][dcdtRandomSequenceLength:])

	return identifier, nonce.Uint64()
}

func boolToSlice(b bool) []byte {
	return []byte(strconv.FormatBool(b))
}
