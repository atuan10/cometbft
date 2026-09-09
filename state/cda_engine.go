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

func getCDAKPieceVal() int {
	if envKPiece := os.Getenv("CDA_K_PIECE"); envKPiece != "" {
		if parsedKPiece, err := strconv.Atoi(envKPiece); err == nil && parsedKPiece > 0 {
			return parsedKPiece
		}
	}
	return getCDAKVal()
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

	// Ensure cells are []byte format
	odsBytes := make([][]byte, len(ods.Cells))
	for i, cell := range ods.Cells {
		if len(cell) == 128 { // Hex encoded cell string
			decoded, err := hex.DecodeString(string(cell))
			if err == nil {
				odsBytes[i] = decoded
				continue
			}
		}
		odsBytes[i] = append([]byte(nil), cell...)
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

// BuildODSFromTxs constructs a K x K Original Data Square from transaction payloads.
func BuildODSFromTxs(txs types.Txs, k int) types.ODSData {
	if len(txs) == 0 {
		return types.ODSData{}
	}
	if k <= 0 {
		k = 32
	}
	targetCells := k * k
	cellSize := 64
	cells := make([][]byte, 0, targetCells)

	for _, tx := range txs {
		txBytes := []byte(tx)
		// If tx is hex-encoded 128 chars, decode it directly
		if len(txBytes) == 128 {
			if decoded, err := hex.DecodeString(string(txBytes)); err == nil && len(decoded) == cellSize {
				cells = append(cells, decoded)
				if len(cells) >= targetCells {
					break
				}
				continue
			}
		}
		// Otherwise chunk into 64-byte slices
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

	// If block ODS data is empty but block has transactions, construct ODS from Txs
	if len(block.Data.ODS.Cells) == 0 && len(block.Data.Txs) > 0 {
		block.Data.ODS = BuildODSFromTxs(block.Data.Txs, getCDAKVal())
	}

	// If block still does not contain ODS data, skip CDA verification
	if len(block.Data.ODS.Cells) == 0 {
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
