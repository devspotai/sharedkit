package util

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// StringArray represents a PostgreSQL TEXT[] array
type StringArray []string

// Value implements the driver.Valuer interface
func (sa StringArray) Value() (driver.Value, error) {
	if sa == nil {
		return nil, nil
	}

	// Format as PostgreSQL array: {item1,item2,item3}
	result := "{"
	for i, item := range sa {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf(`"%s"`, item)
	}
	result += "}"

	return result, nil
}

// Scan implements the sql.Scanner interface
func (sa *StringArray) Scan(value interface{}) error {
	if value == nil {
		*sa = nil
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, sa)
	case string:
		return json.Unmarshal([]byte(v), sa)
	default:
		return fmt.Errorf("cannot scan %T into StringArray", value)
	}
}
