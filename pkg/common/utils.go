package common

import (
	"encoding/json"
	"os"
	"strconv"
)

type UserDetails struct {
	Username string
	Arn      string
}
type RoleDetails struct {
	RoleName string
	Arn      string
}

func StructToMap(s any) (map[string]any, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	// Clean up the result
	cleanResult := make(map[string]any)

	for key, value := range result {
		// Skip null values
		if value == nil {
			continue
		}

		// Convert bools to strings
		if boolVal, ok := value.(bool); ok {
			cleanResult[key] = strconv.FormatBool(boolVal)
		} else {
			cleanResult[key] = value
		}
	}

	return cleanResult, nil
}

func WriteToFile[T any](obj T, filename string) error {
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// For slices
func WriteSliceToFile[T any](objs []T, filepath string) error {
	data, err := json.MarshalIndent(objs, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath, data, 0644)
}
