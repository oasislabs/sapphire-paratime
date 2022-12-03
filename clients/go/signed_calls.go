package sapphire

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

const ZeroAddress = "0x0000000000000000000000000000000000000000"

// Signer is a type that produces secp256k1 signatures in RSV format.
type Signer interface {
	// Sign returns a 65-byte secp256k1 signature as (R || S || V) over the provided digest.
	Sign(digest [32]byte) ([]byte, error)
}

// SignedCallDataPack defines a signed call.
//
// It should be encoded and sent in the `data` field of an Ethereum call.
type SignedCallDataPack struct {
	Data      Data   `json:"data"`
	Leash     Leash  `json:"leash"`
	Signature []byte `json:"signature"`
}

// Part of the datapack
type Data struct {
	Body []byte `json:"body"`
}

// DataEnvelope is an oasis-sdk `Call` without optional fields.
type DataEnvelope struct {
	Body   []byte `json:"body"`
	Format uint64 `json:"format,omitempty"` // reuse for now, TODO swap later
}

// EncryptedBodyEnvelope is an oasis-sdk `Call` with optional fields.
type EncryptedBodyEnvelope struct {
	Body   Body   `json:"body"`
	Format uint64 `json:"format"`
}

type Body struct {
	PK    []byte `json:"pk"`
	Data  []byte `json:"data"`
	Nonce []byte `json:"nonce"`
}

type Leash struct {
	Nonce       uint64 `json:"nonce"`
	BlockNumber uint64 `json:"block_number"`
	BlockHash   []byte `json:"block_hash"`
	BlockRange  uint64 `json:"block_range"`
}

// NewDataPack returns a SignedCallDataPack.
//
// This method does not encrypt `data`, so that should be done afterwards.
func NewDataPack(signer Signer, chainId uint64, caller, callee []byte, gasLimit uint64, gasPrice, value *big.Int, data []byte, leash Leash) (*SignedCallDataPack, error) {
	signable := makeSignableCall(chainId, caller, callee, gasLimit, gasPrice, value, data, leash)
	signature, err := signTypedData(signer, signable)
	if err != nil {
		return nil, fmt.Errorf("failed to sign call: %w", err)
	}
	return &SignedCallDataPack{
		Data:      Data{Body: data},
		Leash:     leash,
		Signature: signature,
	}, nil
}

func (p *SignedCallDataPack) Encode() []byte {
	return hexutil.Bytes(cbor.Marshal(p.Data.Body))
}

func (p *SignedCallDataPack) EncryptEncode(cipher Cipher) []byte {
	// Encrypt when data exists
	if p.Data.Body != nil {
		return cipher.EncryptEncode(p.Data.Body)
	}

	return p.Encode()
}

func NewLeash(nonce uint64, blockNumber uint64, blockHash []byte, blockRange uint64) Leash {
	return Leash{
		Nonce:       nonce,
		BlockNumber: blockNumber,
		BlockHash:   blockHash,
		BlockRange:  blockRange,
	}
}

func makeSignableCall(chainId uint64, caller, callee []byte, gasLimit uint64, gasPrice *big.Int, value *big.Int, data []byte, leash Leash) apitypes.TypedData {
	toAddr := ZeroAddress
	// callee should exist except for contract creation
	if callee != nil {
		toAddr = hex.EncodeToString(callee[:])
	}

	if value == nil {
		value = big.NewInt(0)
	}
	valueU256 := math.HexOrDecimal256(*value)

	if gasPrice == nil {
		gasPrice = big.NewInt(0)
	}
	gasPriceU256 := math.HexOrDecimal256(*gasPrice)

	return apitypes.TypedData{
		Types: map[string][]apitypes.Type{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
			},
			"Call": {
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
				{Name: "gasLimit", Type: "uint64"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "leash", Type: "Leash"},
			},
			"Leash": {
				{Name: "nonce", Type: "uint64"},
				{Name: "blockNumber", Type: "uint64"},
				{Name: "blockHash", Type: "bytes32"},
				{Name: "blockRange", Type: "uint64"},
			},
		},
		PrimaryType: "Call",
		Domain: apitypes.TypedDataDomain{
			Name:              "oasis-runtime-sdk/evm: signed query",
			Version:           "1.0.0",
			ChainId:           math.NewHexOrDecimal256(int64(chainId)),
			VerifyingContract: "",
			Salt:              "",
		},
		Message: map[string]interface{}{
			"from":     hex.EncodeToString(caller[:]),
			"to":       toAddr,
			"value":    &valueU256,
			"gasLimit": math.NewHexOrDecimal256(int64(gasLimit)),
			"gasPrice": &gasPriceU256,
			"data":     data,
			"leash": map[string]interface{}{
				"nonce":       math.NewHexOrDecimal256(int64(leash.Nonce)),
				"blockNumber": math.NewHexOrDecimal256(int64(leash.BlockNumber)),
				"blockHash":   leash.BlockHash,
				"blockRange":  math.NewHexOrDecimal256(int64(leash.BlockRange)),
			},
		},
	}
}

// signTypedData is based on go-ethereum/core/signer but modified to use an in-memory signer.
func signTypedData(signer Signer, typedData apitypes.TypedData) ([]byte, error) {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, fmt.Errorf("failed to hash EIP721Domain: %w", err)
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to hash typed data: %w", err)
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	digest := crypto.Keccak256Hash(rawData)
	signature, err := signer.Sign(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign typed data: %w", err)
	}
	signature[64] = 28 // Eth wallets use a high recovery ID.
	return signature, nil
}
