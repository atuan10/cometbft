package state

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cometbft/cometbft/types"
)

type HeaderPayload struct {
	ChainID         string    `json:"chain_id,omitempty"`
	Height          int64     `json:"height,omitempty"`
	Time            time.Time `json:"time,omitempty"`
	DataHash        string    `json:"data_hash,omitempty"`
	AppHash         string    `json:"app_hash,omitempty"`
	ProposerAddress string    `json:"proposer_address,omitempty"`

	CommitsRoot string   `json:"commits_root,omitempty"`
	ColumnComm  []string `json:"column_comm,omitempty"`
	Coeffs      string   `json:"coeffs,omitempty"`
}

type TxSummary struct {
	Hash   string `json:"hash"`
	Key    string `json:"key,omitempty"`
	Offset int    `json:"offset"`
	Cells  int    `json:"cells"`
	Size   int    `json:"size"`
}

type PublishRequest struct {
	BlockID   string         `json:"block_id"`
	Height    int64          `json:"height,omitempty"`
	K         int            `json:"k,omitempty"`
	Data      []string       `json:"data"`
	Header    *HeaderPayload `json:"header,omitempty"`
	Txs       []TxSummary    `json:"txs,omitempty"`
	Signature string         `json:"signature,omitempty"`
}

type PublisherPusher struct {
	publisherURL string
	client       *http.Client
}

func NewPublisherPusher(url string) *PublisherPusher {
	if url == "" {
		if envURL := os.Getenv("PUBLISHER_URL"); envURL != "" {
			url = envURL
		} else {
			url = "http://localhost:8080/publish"
		}
	}
	timeout := 180 * time.Second
	if envTimeout := os.Getenv("PUBLISHER_TIMEOUT"); envTimeout != "" {
		if d, err := time.ParseDuration(envTimeout); err == nil && d > 0 {
			timeout = d
		}
	}
	return &PublisherPusher{
		publisherURL: url,
		client:       &http.Client{Timeout: timeout},
	}
}

// PushCommittedBlock sends the committed block data to the Publisher Node.
func (p *PublisherPusher) PushCommittedBlock(block *types.Block) error {
	if block == nil || len(block.Data.ODS.Cells) == 0 {
		return nil
	}

	blockID := fmt.Sprintf("block-%d", block.Height)
	if block.Height <= 0 {
		blockID = "block-0-" + block.Header.Hash().String()
	}
	dataHex := make([]string, len(block.Data.ODS.Cells))
	for i, cell := range block.Data.ODS.Cells {
		if len(cell) == 128 {
			dataHex[i] = string(cell)
		} else {
			dataHex[i] = hex.EncodeToString(cell)
		}
	}

	var headerPayload *HeaderPayload
	if len(block.Header.CommitsRoot) > 0 || len(block.Header.ColumnComm) > 0 || len(block.Header.Coeffs) > 0 {
		colCommHex := make([]string, len(block.Header.ColumnComm))
		for i, col := range block.Header.ColumnComm {
			colCommHex[i] = hex.EncodeToString(col)
		}
		headerPayload = &HeaderPayload{
			ChainID:         block.Header.ChainID,
			Height:          block.Header.Height,
			Time:            block.Header.Time,
			DataHash:        hex.EncodeToString(block.Header.DataHash),
			AppHash:         hex.EncodeToString(block.Header.AppHash),
			ProposerAddress: block.Header.ProposerAddress.String(),
			CommitsRoot:     hex.EncodeToString(block.Header.CommitsRoot),
			ColumnComm:      colCommHex,
			Coeffs:          hex.EncodeToString(block.Header.Coeffs),
		}
	}

	cellSize := getCDACellSizeVal()
	hexLen := cellSize * 2
	currentCellOffset := 0
	txSummaries := make([]TxSummary, 0, len(block.Data.Txs))

	for _, tx := range block.Data.Txs {
		txBytes := []byte(tx)
		txHash := strings.ToUpper(hex.EncodeToString(tx.Hash()))
		var txKey string
		txStr := string(txBytes)
		if eqIdx := strings.IndexByte(txStr, '='); eqIdx > 0 {
			txKey = txStr[:eqIdx]
		}

		numCells := 1
		if len(txBytes) == hexLen || len(txBytes) == 128 {
			if _, err := hex.DecodeString(txStr); err == nil {
				numCells = 1
			}
		} else {
			numCells = (len(txBytes) + cellSize - 1) / cellSize
			if numCells <= 0 {
				numCells = 1
			}
		}

		txSummaries = append(txSummaries, TxSummary{
			Hash:   txHash,
			Key:    txKey,
			Offset: currentCellOffset,
			Cells:  numCells,
			Size:   len(txBytes),
		})
		currentCellOffset += numCells
	}

	reqPayload := PublishRequest{
		BlockID: blockID,
		Height:  block.Height,
		Data:    dataHex,
		Header:  headerPayload,
		Txs:     txSummaries,
	}

	bz, err := json.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal publish request: %w", err)
	}

	resp, err := p.client.Post(p.publisherURL, "application/json", bytes.NewBuffer(bz))
	if err != nil {
		log.Printf("[PublisherPusher] Warning: Failed to send block %s to publisher at %s: %v", blockID, p.publisherURL, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := strings.TrimSpace(string(bodyBytes))
		log.Printf("[PublisherPusher] Publisher returned status %d for block %s: %s", resp.StatusCode, blockID, errMsg)
		return fmt.Errorf("publisher returned status %d for block %s: %s", resp.StatusCode, blockID, errMsg)
	}

	log.Printf("[PublisherPusher] Successfully published block %s (height %d) to Publisher Node", blockID, block.Height)
	return nil
}

// CheckPipelineInFlight queries Publisher Node /status to get the current in-flight pipeline count.
// Returns -1 if Publisher is unreachable or auto-publisher-push is disabled.
func CheckPipelineInFlight() int {
	if os.Getenv("DISABLE_AUTO_PUBLISHER_PUSH") == "true" {
		return 0
	}
	pubURL := os.Getenv("PUBLISHER_URL")
	if pubURL == "" {
		pubURL = "http://localhost:8080/publish"
	}
	baseURL := strings.TrimSuffix(pubURL, "/publish")
	statusURL := baseURL + "/status"

	client := &http.Client{Timeout: 250 * time.Millisecond}
	resp, err := client.Get(statusURL)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return -1
	}

	var st struct {
		InFlightCount int `json:"in_flight_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return -1
	}
	return st.InFlightCount
}

