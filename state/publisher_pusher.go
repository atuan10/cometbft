package state

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cometbft/cometbft/types"
)

const BinaryPublishBlockMagic uint32 = 0x43444103 // "CDA\x03"

var (
	localPushesInFlight atomic.Int32

	sharedHTTPTransport = &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	}

	statusHTTPClient = &http.Client{
		Timeout:   250 * time.Millisecond,
		Transport: sharedHTTPTransport,
	}
)

func IncrementLocalPushInFlight() {
	localPushesInFlight.Add(1)
}

func DecrementLocalPushInFlight() {
	for {
		cur := localPushesInFlight.Load()
		if cur <= 0 {
			return
		}
		if localPushesInFlight.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

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

	// Raw binary fields for zero-hex binary wire transfer
	RawDataHash    []byte   `json:"-"`
	RawAppHash     []byte   `json:"-"`
	RawCommitsRoot []byte   `json:"-"`
	RawColumnComm  [][]byte `json:"-"`
	RawCoeffs      []byte   `json:"-"`
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
	RawCells  [][]byte       `json:"-"`
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
		client: &http.Client{
			Timeout:   timeout,
			Transport: sharedHTTPTransport,
		},
	}
}

func writeString16(buf *bytes.Buffer, s string) {
	b := []byte(s)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(b)))
	if len(b) > 0 {
		buf.Write(b)
	}
}

func readString16(r io.Reader) (string, error) {
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return "", err
	}
	if l == 0 {
		return "", nil
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

func writeBytes16(buf *bytes.Buffer, b []byte) {
	_ = binary.Write(buf, binary.BigEndian, uint16(len(b)))
	if len(b) > 0 {
		buf.Write(b)
	}
}

func readBytes16(r io.Reader) ([]byte, error) {
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	if l == 0 {
		return nil, nil
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// EncodeBinaryPublishRequest serializes a PublishRequest into the compact binary wire format (CDA\x03) without hex encoding
func EncodeBinaryPublishRequest(req *PublishRequest) ([]byte, error) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, BinaryPublishBlockMagic)

	writeString16(&buf, req.BlockID)
	_ = binary.Write(&buf, binary.BigEndian, req.Height)
	_ = binary.Write(&buf, binary.BigEndian, uint16(req.K))

	cells := req.RawCells
	if len(cells) == 0 && len(req.Data) > 0 {
		cells = make([][]byte, len(req.Data))
		for i, h := range req.Data {
			if decoded, err := hex.DecodeString(h); err == nil {
				cells[i] = decoded
			} else {
				cells[i] = []byte(h)
			}
		}
	}

	_ = binary.Write(&buf, binary.BigEndian, uint32(len(cells)))
	for _, cell := range cells {
		writeBytes16(&buf, cell)
	}

	if req.Header != nil {
		buf.WriteByte(1)
		writeString16(&buf, req.Header.ChainID)
		_ = binary.Write(&buf, binary.BigEndian, req.Header.Height)
		_ = binary.Write(&buf, binary.BigEndian, req.Header.Time.UnixNano())

		dataHash := req.Header.RawDataHash
		if len(dataHash) == 0 && req.Header.DataHash != "" {
			dataHash, _ = hex.DecodeString(req.Header.DataHash)
		}
		writeBytes16(&buf, dataHash)

		appHash := req.Header.RawAppHash
		if len(appHash) == 0 && req.Header.AppHash != "" {
			appHash, _ = hex.DecodeString(req.Header.AppHash)
		}
		writeBytes16(&buf, appHash)

		writeString16(&buf, req.Header.ProposerAddress)

		commitsRoot := req.Header.RawCommitsRoot
		if len(commitsRoot) == 0 && req.Header.CommitsRoot != "" {
			commitsRoot, _ = hex.DecodeString(req.Header.CommitsRoot)
		}
		writeBytes16(&buf, commitsRoot)

		rawCols := req.Header.RawColumnComm
		if len(rawCols) == 0 && len(req.Header.ColumnComm) > 0 {
			rawCols = make([][]byte, len(req.Header.ColumnComm))
			for i, ccHex := range req.Header.ColumnComm {
				rawCols[i], _ = hex.DecodeString(ccHex)
			}
		}
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(rawCols)))
		for _, cc := range rawCols {
			writeBytes16(&buf, cc)
		}

		coeffs := req.Header.RawCoeffs
		if len(coeffs) == 0 && req.Header.Coeffs != "" {
			coeffs, _ = hex.DecodeString(req.Header.Coeffs)
		}
		writeBytes16(&buf, coeffs)
	} else {
		buf.WriteByte(0)
	}

	_ = binary.Write(&buf, binary.BigEndian, uint32(len(req.Txs)))
	for _, tx := range req.Txs {
		writeString16(&buf, tx.Hash)
		writeString16(&buf, tx.Key)
		_ = binary.Write(&buf, binary.BigEndian, uint32(tx.Offset))
		_ = binary.Write(&buf, binary.BigEndian, uint32(tx.Cells))
		_ = binary.Write(&buf, binary.BigEndian, uint32(tx.Size))
	}

	var sigBytes []byte
	if req.Signature != "" {
		sigBytes, _ = hex.DecodeString(req.Signature)
	}
	writeBytes16(&buf, sigBytes)

	return buf.Bytes(), nil
}

// DecodePublishRequest decodes either a binary CDA\x03 payload or a JSON PublishRequest
func DecodePublishRequest(r io.Reader) (*PublishRequest, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(body) >= 4 && binary.BigEndian.Uint32(body[:4]) == BinaryPublishBlockMagic {
		br := bytes.NewReader(body[4:])
		blockID, err := readString16(br)
		if err != nil {
			return nil, err
		}
		var height int64
		if err := binary.Read(br, binary.BigEndian, &height); err != nil {
			return nil, err
		}
		var kVal uint16
		if err := binary.Read(br, binary.BigEndian, &kVal); err != nil {
			return nil, err
		}
		var numCells uint32
		if err := binary.Read(br, binary.BigEndian, &numCells); err != nil {
			return nil, err
		}
		rawCells := make([][]byte, numCells)
		dataHex := make([]string, numCells)
		for i := 0; i < int(numCells); i++ {
			c, err := readBytes16(br)
			if err != nil {
				return nil, err
			}
			rawCells[i] = c
			if len(c) == 128 {
				dataHex[i] = string(c)
			} else {
				dataHex[i] = hex.EncodeToString(c)
			}
		}

		var hasHeader uint8
		if err := binary.Read(br, binary.BigEndian, &hasHeader); err != nil {
			return nil, err
		}
		var hdr *HeaderPayload
		if hasHeader == 1 {
			chainID, err := readString16(br)
			if err != nil {
				return nil, err
			}
			var hHeight, timeNano int64
			if err := binary.Read(br, binary.BigEndian, &hHeight); err != nil {
				return nil, err
			}
			if err := binary.Read(br, binary.BigEndian, &timeNano); err != nil {
				return nil, err
			}
			dataHash, err := readBytes16(br)
			if err != nil {
				return nil, err
			}
			appHash, err := readBytes16(br)
			if err != nil {
				return nil, err
			}
			propAddr, err := readString16(br)
			if err != nil {
				return nil, err
			}
			commitsRoot, err := readBytes16(br)
			if err != nil {
				return nil, err
			}
			var numCols uint16
			if err := binary.Read(br, binary.BigEndian, &numCols); err != nil {
				return nil, err
			}
			rawCols := make([][]byte, numCols)
			colHex := make([]string, numCols)
			for i := 0; i < int(numCols); i++ {
				cc, err := readBytes16(br)
				if err != nil {
					return nil, err
				}
				rawCols[i] = cc
				colHex[i] = hex.EncodeToString(cc)
			}
			coeffs, err := readBytes16(br)
			if err != nil {
				return nil, err
			}
			hdr = &HeaderPayload{
				ChainID:         chainID,
				Height:          hHeight,
				Time:            time.Unix(0, timeNano).UTC(),
				DataHash:        hex.EncodeToString(dataHash),
				AppHash:         hex.EncodeToString(appHash),
				ProposerAddress: propAddr,
				CommitsRoot:     hex.EncodeToString(commitsRoot),
				ColumnComm:      colHex,
				Coeffs:          hex.EncodeToString(coeffs),
				RawDataHash:     dataHash,
				RawAppHash:      appHash,
				RawCommitsRoot:  commitsRoot,
				RawColumnComm:   rawCols,
				RawCoeffs:       coeffs,
			}
		}

		var numTxs uint32
		if err := binary.Read(br, binary.BigEndian, &numTxs); err != nil {
			return nil, err
		}
		txs := make([]TxSummary, numTxs)
		for i := 0; i < int(numTxs); i++ {
			txHash, err := readString16(br)
			if err != nil {
				return nil, err
			}
			txKey, err := readString16(br)
			if err != nil {
				return nil, err
			}
			var offset, numC, sz uint32
			if err := binary.Read(br, binary.BigEndian, &offset); err != nil {
				return nil, err
			}
			if err := binary.Read(br, binary.BigEndian, &numC); err != nil {
				return nil, err
			}
			if err := binary.Read(br, binary.BigEndian, &sz); err != nil {
				return nil, err
			}
			txs[i] = TxSummary{
				Hash:   txHash,
				Key:    txKey,
				Offset: int(offset),
				Cells:  int(numC),
				Size:   int(sz),
			}
		}
		sigBytes, err := readBytes16(br)
		if err != nil {
			return nil, err
		}
		return &PublishRequest{
			BlockID:   blockID,
			Height:    height,
			K:         int(kVal),
			Data:      dataHex,
			RawCells:  rawCells,
			Header:    hdr,
			Txs:       txs,
			Signature: hex.EncodeToString(sigBytes),
		}, nil
	}

	var req PublishRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// PushCommittedBlock sends the committed block data to the Publisher Node using the binary wire protocol.
func (p *PublisherPusher) PushCommittedBlock(block *types.Block) error {
	if block == nil || len(block.Data.ODS.Cells) == 0 {
		return nil
	}

	blockID := fmt.Sprintf("block-%d", block.Height)
	if block.Height <= 0 {
		blockID = "block-0-" + block.Header.Hash().String()
	}

	cellSize := getCDACellSizeVal()
	rawCells := make([][]byte, len(block.Data.ODS.Cells))
	for i, cell := range block.Data.ODS.Cells {
		if len(cell) == 128 || len(cell) == 2*cellSize {
			if decoded, err := hex.DecodeString(string(cell)); err == nil {
				rawCells[i] = decoded
				continue
			}
		}
		rawCells[i] = cell
	}

	var headerPayload *HeaderPayload
	if len(block.Header.CommitsRoot) > 0 || len(block.Header.ColumnComm) > 0 || len(block.Header.Coeffs) > 0 {
		rawCols := make([][]byte, len(block.Header.ColumnComm))
		for i, col := range block.Header.ColumnComm {
			rawCols[i] = col
		}
		headerPayload = &HeaderPayload{
			ChainID:         block.Header.ChainID,
			Height:          block.Header.Height,
			Time:            block.Header.Time,
			ProposerAddress: block.Header.ProposerAddress.String(),
			RawDataHash:     block.Header.DataHash,
			RawAppHash:      block.Header.AppHash,
			RawCommitsRoot:  block.Header.CommitsRoot,
			RawColumnComm:   rawCols,
			RawCoeffs:       block.Header.Coeffs,
		}
	}

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
		BlockID:  blockID,
		Height:   block.Height,
		K:        block.Data.ODS.K,
		RawCells: rawCells,
		Header:   headerPayload,
		Txs:      txSummaries,
	}

	bz, err := EncodeBinaryPublishRequest(&reqPayload)
	if err != nil {
		return fmt.Errorf("failed to encode binary publish request: %w", err)
	}

	resp, err := p.client.Post(p.publisherURL, "application/octet-stream", bytes.NewReader(bz))
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

	log.Printf("[PublisherPusher] Successfully published block %s (height %d) to Publisher Node (binary %d bytes)", blockID, block.Height, len(bz))
	return nil
}

// CheckPipelineInFlight queries Publisher Node /status to get the current in-flight pipeline count.
// Returns -1 if Publisher is unreachable or backpressure is disabled.
func CheckPipelineInFlight() int {
	if os.Getenv("DISABLE_CDA_BACKPRESSURE") == "true" {
		return 0
	}
	pubURL := os.Getenv("PUBLISHER_URL")
	if pubURL == "" {
		if os.Getenv("DISABLE_AUTO_PUBLISHER_PUSH") == "true" {
			return 0
		}
		pubURL = "http://localhost:8080/publish"
	}
	baseURL := strings.TrimSuffix(pubURL, "/publish")
	statusURL := baseURL + "/status"

	resp, err := statusHTTPClient.Get(statusURL)
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
	if local := int(localPushesInFlight.Load()); local > st.InFlightCount {
		return local
	}
	return st.InFlightCount
}

