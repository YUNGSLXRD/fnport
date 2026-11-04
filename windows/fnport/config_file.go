package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func readAWGConfigFile(path string) (string, error) {
	if !strings.EqualFold(filepath.Ext(path), ".conf") {
		return "", errors.New("выберите файл AmneziaWG с расширением .conf")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("не удалось открыть файл конфигурации")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("нужен обычный файл конфигурации")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return "", errors.New("не удалось прочитать файл конфигурации")
	}
	if len(b) > 1<<20 {
		return "", errors.New("файл конфигурации больше 1 МБ")
	}
	if !utf8.Valid(b) {
		return "", errors.New("файл конфигурации должен быть в UTF-8")
	}
	text := string(b)
	if _, err := importAWGConf(text); err != nil {
		return "", err
	}
	return text, nil
}
