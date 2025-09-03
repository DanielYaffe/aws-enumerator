package common

import (
	"encoding/json"
	"os"
	"reflect"
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

func StructToMap(s any) map[string]any {
	result := make(map[string]any)
	v := reflect.ValueOf(s)
	t := reflect.TypeOf(s)

	// Handle pointer to struct
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return result
		}
		v = v.Elem()
		t = t.Elem()
	}

	if v.Kind() != reflect.Struct {
		return result
	}

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		fieldName := fieldType.Name

		var value any
		if field.Kind() == reflect.Pointer {
			if field.IsNil() {
				continue // Skip nil values
			}
			value = field.Elem().Interface()
		} else if field.Kind() == reflect.Slice && field.IsNil() {
			continue
		} else {
			value = field.Interface()
		}

		if value == nil {
			continue
		}
		// Convert bools to strings
		if boolVal, ok := value.(bool); ok {
			result[fieldName] = strconv.FormatBool(boolVal)
		} else {
			result[fieldName] = value
		}
	}

	return result
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
