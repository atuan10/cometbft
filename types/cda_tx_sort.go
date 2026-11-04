package types

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CDATxCategory represents the sorting priority category of a transaction.
type CDATxCategory int

const (
	// CategorySystem represents system/consensus transactions (e.g. validator updates).
	CategorySystem CDATxCategory = iota
	// CategoryCDANamespace represents CDA namespace-indexed data blobs and slices.
	CategoryCDANamespace
	// CategoryKeyValue represents arbitrary key-value application transactions.
	CategoryKeyValue
	// CategoryOpaque represents raw opaque transaction payloads.
	CategoryOpaque
)

// CDATxSortKey contains decomposed fields of a transaction for canonical ordering.
type CDATxSortKey struct {
	Category  CDATxCategory
	Namespace string
	BlobID    string
	Subtype   int // 0: meta/manifest, 1: slice, 2: other
	ChunkIdx  int
	SliceIdx  int
	RawKey    string
	RawTx     []byte
}

// ParseCDATxSortKey parses a transaction byte slice into a structured sort key.
func ParseCDATxSortKey(tx []byte) CDATxSortKey {
	key := CDATxSortKey{
		RawTx: tx,
	}

	txStr := string(tx)

	// Check for validator updates or system transactions (e.g. "val:pubkey/power")
	if strings.HasPrefix(txStr, "val:") || strings.HasPrefix(txStr, "val=") {
		key.Category = CategorySystem
		key.RawKey = txStr
		return key
	}

	// Extract key and value boundary
	var rawKey string
	if eqIdx := strings.IndexByte(txStr, '='); eqIdx >= 0 {
		rawKey = txStr[:eqIdx]
	} else if colonIdx := strings.IndexByte(txStr, ':'); colonIdx >= 0 {
		rawKey = txStr[:colonIdx]
	}

	if rawKey == "" {
		// No key delimiter found; treat as opaque or use full string
		key.Category = CategoryOpaque
		key.RawKey = txStr
		return key
	}

	key.RawKey = rawKey

	// Check if this is a CDA namespace URI key: "cda/<namespace>/<blob_id>/..."
	if strings.HasPrefix(rawKey, "cda/") {
		parts := strings.Split(rawKey, "/")
		if len(parts) >= 4 {
			key.Category = CategoryCDANamespace
			key.Namespace = parts[1]
			key.BlobID = parts[2]

			typePart := parts[3]
			switch typePart {
			case "meta", "manifest":
				key.Subtype = 0
			case "blob":
				key.Subtype = 1
			case "part":
				key.Subtype = 2
				if len(parts) >= 5 {
					if p, err := strconv.Atoi(parts[4]); err == nil {
						key.ChunkIdx = p
					}
				}
			case "s", "slice":
				key.Subtype = 3
				if len(parts) >= 5 {
					seqPart := parts[4]
					if strings.Contains(seqPart, "_") {
						subParts := strings.SplitN(seqPart, "_", 2)
						if c, err := strconv.Atoi(subParts[0]); err == nil {
							key.ChunkIdx = c
						}
						if s, err := strconv.Atoi(subParts[1]); err == nil {
							key.SliceIdx = s
						}
					} else {
						if s, err := strconv.Atoi(seqPart); err == nil {
							key.SliceIdx = s
						}
					}
				}
			default:
				key.Subtype = 4
			}
			return key
		} else if len(parts) == 3 {
			// "cda/<namespace>/<blob_id>"
			key.Category = CategoryCDANamespace
			key.Namespace = parts[1]
			key.BlobID = parts[2]
			key.Subtype = 1 // Treat as blob
			return key
		}
	}

	// Standard Key-Value transaction
	key.Category = CategoryKeyValue
	return key
}

// CompareCDATxs compares two transaction byte slices according to canonical CDA namespace ordering.
// Returns:
//   - < 0 if txA < txB
//   - 0 if txA == txB
//   - > 0 if txA > txB
func CompareCDATxs(txA, txB []byte) int {
	if bytes.Equal(txA, txB) {
		return 0
	}

	keyA := ParseCDATxSortKey(txA)
	keyB := ParseCDATxSortKey(txB)

	// 1. Compare Category
	if keyA.Category != keyB.Category {
		return int(keyA.Category) - int(keyB.Category)
	}

	// 2. Category-specific comparisons
	switch keyA.Category {
	case CategoryCDANamespace:
		// 2.1 Namespace lexicographical order
		if cmp := strings.Compare(keyA.Namespace, keyB.Namespace); cmp != 0 {
			return cmp
		}

		// 2.2 BlobID lexicographical order
		if cmp := strings.Compare(keyA.BlobID, keyB.BlobID); cmp != 0 {
			return cmp
		}

		// 2.3 Subtype order (meta/manifest = 0, blob = 1, part = 2, slices = 3, other = 4)
		if keyA.Subtype != keyB.Subtype {
			return keyA.Subtype - keyB.Subtype
		}

		// 2.4 Multi-part blobs: compare PartIdx (stored in ChunkIdx) numerically
		if keyA.Subtype == 2 {
			if keyA.ChunkIdx != keyB.ChunkIdx {
				return keyA.ChunkIdx - keyB.ChunkIdx
			}
		}

		// 2.5 Legacy Slices: compare ChunkIdx then SliceIdx numerically
		if keyA.Subtype == 3 {
			if keyA.ChunkIdx != keyB.ChunkIdx {
				return keyA.ChunkIdx - keyB.ChunkIdx
			}
			if keyA.SliceIdx != keyB.SliceIdx {
				return keyA.SliceIdx - keyB.SliceIdx
			}
		}

		// 2.5 RawKey tie-breaker
		if cmp := strings.Compare(keyA.RawKey, keyB.RawKey); cmp != 0 {
			return cmp
		}

		// 2.6 Full transaction bytes tie-breaker
		return bytes.Compare(txA, txB)

	case CategorySystem, CategoryKeyValue:
		// Lexicographical comparison of RawKey
		if cmp := strings.Compare(keyA.RawKey, keyB.RawKey); cmp != 0 {
			return cmp
		}
		// Full transaction bytes tie-breaker
		return bytes.Compare(txA, txB)

	case CategoryOpaque:
		return bytes.Compare(txA, txB)
	}

	return bytes.Compare(txA, txB)
}

// SortCDATxs sorts a slice of transactions in-place using canonical CDA namespace ordering.
func SortCDATxs(txs Txs) {
	if len(txs) <= 1 {
		return
	}
	sort.SliceStable(txs, func(i, j int) bool {
		return CompareCDATxs(txs[i], txs[j]) < 0
	})
}

// IsCDATxsSorted checks whether the given transactions are strictly in non-decreasing canonical order.
// If not, it returns false along with a descriptive error specifying the out-of-order index and keys.
func IsCDATxsSorted(txs Txs) (bool, error) {
	if len(txs) <= 1 {
		return true, nil
	}

	for i := 0; i < len(txs)-1; i++ {
		cmp := CompareCDATxs(txs[i], txs[i+1])
		if cmp > 0 {
			keyCurrent := ParseCDATxSortKey(txs[i])
			keyNext := ParseCDATxSortKey(txs[i+1])
			return false, fmt.Errorf("transaction at index %d [key=%q, cat=%d] out of canonical order relative to index %d [key=%q, cat=%d]",
				i, keyCurrent.RawKey, keyCurrent.Category,
				i+1, keyNext.RawKey, keyNext.Category)
		}
	}

	return true, nil
}
