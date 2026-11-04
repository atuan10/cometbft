package state

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"sync"

	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"

	"github.com/cometbft/cometbft/types"
)

func getCDAKVal() int {
	if envK := os.Getenv("CDA_K"); envK != "" {
		if parsedK, err := strconv.Atoi(envK); err == nil && parsedK > 0 {
			return parsedK
		}
	}
	return 32
}

func getCDAMaxKVal() int {
	return types.GetCDAMaxK()
}

func getCDAKPieceVal() int {
	if envKPiece := os.Getenv("CDA_K_PIECE"); envKPiece != "" {
		if parsedKPiece, err := strconv.Atoi(envKPiece); err == nil && parsedKPiece > 0 {
			return parsedKPiece
		}
	}
	return 4
}

func getCDACellSizeVal() int {
	return types.GetCDACellSize()
}

var (
	cdaOnce sync.Once
	cdaKZG  *cda.GnarkKZG
	cdaErr  error
)

func getKZGProvider() (*cda.GnarkKZG, error) {
	cdaOnce.Do(func() {
		srsSize := uint64(1024)
		srs, err := bls12381kzg.NewSRS(srsSize, big.NewInt(-1))
		if err != nil {
			cdaErr = fmt.Errorf("failed to create SRS for CDA engine: %w", err)
			return
		}
		cdaKZG = cda.NewGnarkKZG(*srs)
	})
	return cdaKZG, cdaErr
}

// ComputeCDAHeader computes CommitsRoot, ColumnComm, and Coeffs for the given ODSData.
func ComputeCDAHeader(ods *types.ODSData) (commitsRoot []byte, columnComm [][]byte, coeffs []byte, err error) {
	if ods == nil || len(ods.Cells) == 0 {
		return nil, nil, nil, nil
	}

	kzg, err := getKZGProvider()
	if err != nil {
		return nil, nil, nil, err
	}

	k := ods.K
	if k <= 0 {
		k = 32 // default ODS dimension if not specified
	}

	// Ensure cells are []byte format and match cell size
	cellSize := getCDACellSizeVal()
	odsBytes := make([][]byte, len(ods.Cells))
	for i, cell := range ods.Cells {
		if len(cell) == 128 || len(cell) == 2*cellSize { // Hex encoded cell string
			decoded, err := hex.DecodeString(string(cell))
			if err == nil {
				cell = decoded
			}
		}
		if len(cell) < cellSize {
			padded := make([]byte, cellSize)
			copy(padded, cell)
			odsBytes[i] = padded
		} else {
			odsBytes[i] = append([]byte(nil), cell...)
		}
	}

	// 1. Compute Extended Data Square (EDS) using RS Leopard codec
	eds, err := cda.ComputeExtendedDataSquareWithLeopard(odsBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute EDS: %w", err)
	}

	// 2. Compute Kate Column Commitments
	kPiece := getCDAKPieceVal()
	codec := rlnc.NewRLNCCodec(kPiece)
	pubData, err := cda.ComputeAndSetKateCommitments(codec, &eds, kzg, 0)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute Kate commitments: %w", err)
	}

	// 3. Build Merkle Tree of piece commitments
	pieceCommitsBytes := make([][]byte, len(pubData.PieceComm))
	for i := range pubData.PieceComm {
		pieceCommitsBytes[i] = append([]byte(nil), pubData.PieceComm[i]...)
	}
	root, _ := cda.BuildMerkleTree(pieceCommitsBytes)

	columnComm = make([][]byte, len(pubData.ColumnComm))
	for i := range pubData.ColumnComm {
		columnComm[i] = append([]byte(nil), pubData.ColumnComm[i]...)
	}

	var coeffBytes []byte
	if len(pubData.Coeffs) > 0 {
		coeffBytes = append([]byte(nil), pubData.Coeffs[0]...)
	}

	return root, columnComm, coeffBytes, nil
}

// CountCellsFromTx counts the number of cells required to store a single tx.
func CountCellsFromTx(tx types.Tx, cellSize int) int {
	return types.CountCellsFromTx(tx, cellSize)
}

// CountCellsFromTxs counts the number of cells required to store txs using configured cell size.
func CountCellsFromTxs(txs types.Txs) int {
	return types.CountCellsFromTxs(txs)
}

// BuildODSFromTxs constructs a K x K Original Data Square from transaction payloads.
// If k <= 0, K is automatically chosen using cda.ComputeOptimalODSK.
func BuildODSFromTxs(txs types.Txs, k int) types.ODSData {
	if k <= 0 {
		k = cda.ComputeOptimalODSK(CountCellsFromTxs(txs), cda.DefaultMinODSK, getCDAMaxKVal())
	}
	targetCells := k * k
	cellSize := getCDACellSizeVal()
	cells := make([][]byte, 0, targetCells)
	hexLen := cellSize * 2

	for _, tx := range txs {
		txBytes := []byte(tx)
		// If tx is hex-encoded matching cell size (or legacy 128 chars), decode it directly
		if len(txBytes) == hexLen || len(txBytes) == 128 {
			if decoded, err := hex.DecodeString(string(txBytes)); err == nil {
				if len(decoded) == cellSize {
					cells = append(cells, decoded)
					if len(cells) >= targetCells {
						break
					}
					continue
				} else if len(decoded) < cellSize {
					padded := make([]byte, cellSize)
					copy(padded, decoded)
					cells = append(cells, padded)
					if len(cells) >= targetCells {
						break
					}
					continue
				}
			}
		}
		// Otherwise chunk into cellSize slices
		for len(txBytes) > 0 {
			chunkLen := cellSize
			if len(txBytes) < chunkLen {
				chunkLen = len(txBytes)
			}
			cell := make([]byte, cellSize)
			copy(cell, txBytes[:chunkLen])
			cells = append(cells, cell)
			txBytes = txBytes[chunkLen:]
			if len(cells) >= targetCells {
				break
			}
		}
		if len(cells) >= targetCells {
			break
		}
	}

	// Pad remaining cells up to targetCells
	for i := len(cells); i < targetCells; i++ {
		cell := make([]byte, cellSize)
		cell[0] = byte(i >> 24)
		cell[1] = byte(i >> 16)
		cell[2] = byte(i >> 8)
		cell[3] = byte(i)
		cells = append(cells, cell)
	}

	return types.ODSData{
		K:     k,
		Cells: cells,
	}
}

// VerifyCDAHeader validates that the Header CDA fields match the block ODS data.
func VerifyCDAHeader(block *types.Block) error {
	if block == nil {
		return fmt.Errorf("nil block")
	}

	// 1. Verify Canonical CDA Namespace Ordering:
	// All transactions in a proposed/committed block MUST strictly adhere to Canonical Namespace Ordering.
	if len(block.Data.Txs) > 0 {
		if sorted, err := types.IsCDATxsSorted(block.Data.Txs); !sorted {
			return fmt.Errorf("invalid block transaction order: %w", err)
		}

		// 2. Enforce CDA Data Availability Invariant:
		// Total cells required by all block transactions MUST NOT exceed maximum ODS matrix capacity.
		maxK := getCDAMaxKVal()
		maxODSCells := maxK * maxK
		if cellsNeeded := CountCellsFromTxs(block.Data.Txs); cellsNeeded > maxODSCells {
			return fmt.Errorf("block transactions require %d cells, exceeding maximum ODS capacity of %d cells (K=%d)",
				cellsNeeded, maxODSCells, maxK)
		}
	}

	// If block ODS data is empty but block has transactions, construct ODS from Txs
	if len(block.Data.ODS.Cells) == 0 && len(block.Data.Txs) > 0 {
		block.Data.ODS = BuildODSFromTxs(block.Data.Txs, 0)
	}

	// If block still does not contain ODS data, skip CDA verification
	if len(block.Data.ODS.Cells) == 0 {
		return nil
	}

	// If block Header has no CDA commitments, skip CDA verification
	if len(block.Header.CommitsRoot) == 0 && len(block.Header.ColumnComm) == 0 {
		return nil
	}

	expectedRoot, expectedCols, expectedCoeffs, err := ComputeCDAHeader(&block.Data.ODS)
	if err != nil {
		return fmt.Errorf("failed to recompute CDA header: %w", err)
	}

	if hex.EncodeToString(block.Header.CommitsRoot) != hex.EncodeToString(expectedRoot) {
		return fmt.Errorf("mismatched CommitsRoot: header=%x, expected=%x", block.Header.CommitsRoot, expectedRoot)
	}

	if len(block.Header.ColumnComm) != len(expectedCols) {
		return fmt.Errorf("mismatched ColumnComm count: header=%d, expected=%d", len(block.Header.ColumnComm), len(expectedCols))
	}

	if hex.EncodeToString(block.Header.Coeffs) != hex.EncodeToString(expectedCoeffs) {
		return fmt.Errorf("mismatched Coeffs: header=%x, expected=%x", block.Header.Coeffs, expectedCoeffs)
	}

	return nil
}
