package utils

import "os"

func ReadFile(file string) (string, error) {
	_, err := os.Stat(file)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
