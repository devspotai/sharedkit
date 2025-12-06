package util

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type JSONB map[string]any

func (j JSONB) Value() (driver.Value, error) {
	return json.Marshal(j)
}

func (j *JSONB) Scan(value any) error {
	if value == nil {
		*j = JSONB{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), j)
	}
	return json.Unmarshal(bytes, j)
}

// shared helper
func ScanJSONSlice[S ~[]E, E any](src any, dest *S) error {
	// Treat NULL as empty array
	if src == nil {
		*dest = (*dest)[:0]
		return nil
	}

	var b []byte
	switch v := src.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	case json.RawMessage:
		b = []byte(v)
	default:
		// Fallback: if the driver gave us a decoded value (map/slice/etc.),
		// try encoding it back to JSON and continue.
		j, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("scanJSONSlice: unsupported src type %T: %w", src, err)
		}
		b = j
	}

	// Empty -> empty slice
	if len(b) == 0 {
		*dest = (*dest)[:0]
		return nil
	}

	// Unmarshal into []E (plain slice), then cast to S (named slice)
	var tmp []E
	if err := json.Unmarshal(b, &tmp); err != nil {
		return fmt.Errorf("scanJSONSlice: unmarshal failed: %w", err)
	}
	*dest = S(tmp)
	return nil
}

// ToRawMessage marshals any typed value into RawMessage.
func ToRawMessage(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// FromRawMessage unmarshals RawMessage into a typed value.
func FromRawMessage[T any](rm json.RawMessage) (T, error) {
	var zero T
	if len(rm) == 0 || string(rm) == "null" {
		return zero, nil
	}
	var out T
	return out, json.Unmarshal(rm, &out)
}
