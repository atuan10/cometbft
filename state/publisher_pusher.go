package state

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cometbft/cometbft/types"
)

type PublishRequest struct {
	BlockID   string   `json:"block_id"`
	Data      []string `json:"data"`
	Signature string   `json:"signature,omitempty"`
}

type PublisherPusher struct {
	publisherURL string
	client       *http.Client
}

func NewPublisherPusher(url string) *PublisherPusher {
	if url == "" {
		url = "http://localhost:8080/publish"
	}
	return &PublisherPusher{
		publisherURL: url,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

// PushCommittedBlock sends the committed block data to the Publisher Node.
func (p *PublisherPusher) PushCommittedBlock(block *types.Block) error {
	if block == nil || len(block.Data.ODS.Cells) == 0 {
		return nil
	}

	blockID := block.Header.Hash().String()
	dataHex := make([]string, len(block.Data.ODS.Cells))
	for i, cell := range block.Data.ODS.Cells {
		if len(cell) == 128 {
			dataHex[i] = string(cell)
		} else {
			dataHex[i] = hex.EncodeToString(cell)
		}
	}

	reqPayload := PublishRequest{
		BlockID: blockID,
		Data:    dataHex,
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
		log.Printf("[PublisherPusher] Publisher returned status %d for block %s", resp.StatusCode, blockID)
	} else {
		log.Printf("[PublisherPusher] Successfully published block %s (height %d) to Publisher Node", blockID, block.Height)
	}

	return nil
}
