package file

import (
	"io/ioutil"
	"os"
)

// Exists checks if file exists
func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// SaveToFile byte
func SaveToFile(filename string, data []byte) bool {
	err := ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		return false
	}
	return true
}
