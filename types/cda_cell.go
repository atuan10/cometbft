package types

import (
	"encoding/hex"
	"os"
	"strconv"
)

const (
	// DefaultCDACellSize is the standard payload byte size per ODS cell (512 bytes).
	DefaultCDACellSize = 512

	// DefaultCDAMaxK is the default maximum ODS matrix dimension (K = 64).
	DefaultCDAMaxK = 64
)

// GetCDACellSize returns the configured ODS cell size in bytes (default: 512).
func GetCDACellSize() int {
	if envCellSize := os.Getenv("CDA_CELL_SIZE"); envCellSize != "" {
		if parsedSize, err := strconv.Atoi(envCellSize); err == nil && parsedSize > 0 {
			return parsedSize
		}
	}
	return DefaultCDACellSize
}

// GetCDAMaxK returns the maximum ODS dimension K (default: 64).
func GetCDAMaxK() int {
	if envMaxK := os.Getenv("CDA_MAX_K"); envMaxK != "" {
		if parsedMaxK, err := strconv.Atoi(envMaxK); err == nil && parsedMaxK > 0 {
			return parsedMaxK
		}
	}
	if envK := os.Getenv("CDA_K"); envK != "" {
		if parsedK, err := strconv.Atoi(envK); err == nil && parsedK > 0 {
			if parsedK > 64 {
				return parsedK
			}
			return 64
		}
	}
	return DefaultCDAMaxK
}

// GetCDAMaxODSCells returns the maximum number of cells an ODS matrix can hold (K_max * K_max).
func GetCDAMaxODSCells() int {
	maxK := GetCDAMaxK()
	return maxK * maxK
}

// GetCDAMaxODSBytes returns the maximum byte capacity of an ODS matrix (maxODSCells * cellSize).
func GetCDAMaxODSBytes() int64 {
	return int64(GetCDAMaxODSCells() * GetCDACellSize())
}

// CountCellsFromTx counts the number of cells required to store a single transaction payload.
func CountCellsFromTx(tx Tx, cellSize int) int {
	if cellSize <= 0 {
		cellSize = GetCDACellSize()
	}
	txBytes := []byte(tx)
	hexLen := cellSize * 2
	if len(txBytes) == hexLen || len(txBytes) == 128 {
		if _, err := hex.DecodeString(string(txBytes)); err == nil {
			return 1
		}
	}
	chunks := (len(txBytes) + cellSize - 1) / cellSize
	if chunks <= 0 {
		chunks = 1
	}
	return chunks
}

// CountCellsFromTxs counts the number of cells required to store a slice of transactions.
func CountCellsFromTxs(txs Txs) int {
	cellSize := GetCDACellSize()
	count := 0
	for _, tx := range txs {
		count += CountCellsFromTx(tx, cellSize)
	}
	return count
}
