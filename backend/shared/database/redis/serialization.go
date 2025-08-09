package redis

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"
)

// SerializeObject serializes an object using the specified format
func SerializeObject(obj interface{}, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.Marshal(obj)
	case "msgpack":
		return msgpack.Marshal(obj)
	default:
		return json.Marshal(obj)
	}
}

// DeserializeObject deserializes data into an object using the specified format
func DeserializeObject(data []byte, obj interface{}, format string) error {
	switch format {
	case "json":
		return json.Unmarshal(data, obj)
	case "msgpack":
		return msgpack.Unmarshal(data, obj)
	default:
		return json.Unmarshal(data, obj)
	}
}

// CompressData compresses data using the specified algorithm
func CompressData(data []byte, config CompressionConfig) ([]byte, error) {
	switch config.Algorithm {
	case "gzip":
		return compressGzip(data, config.Level)
	case "lz4":
		return compressLZ4(data)
	default:
		return compressLZ4(data) // Default to LZ4 for speed
	}
}

// DecompressData decompresses data using the specified algorithm
func DecompressData(data []byte, config CompressionConfig) ([]byte, error) {
	switch config.Algorithm {
	case "gzip":
		return decompressGzip(data)
	case "lz4":
		return decompressLZ4(data)
	default:
		return decompressLZ4(data) // Default to LZ4
	}
}

// compressGzip compresses data using gzip
func compressGzip(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	
	writer, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip writer: %w", err)
	}
	defer writer.Close()

	_, err = writer.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write compressed data: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressGzip decompresses gzip data
func decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	return decompressed, nil
}

// compressLZ4 compresses data using LZ4
func compressLZ4(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	
	writer := lz4.NewWriter(&buf)
	defer writer.Close()

	_, err := writer.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write LZ4 compressed data: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close LZ4 writer: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressLZ4 decompresses LZ4 data
func decompressLZ4(data []byte) ([]byte, error) {
	reader := lz4.NewReader(bytes.NewReader(data))
	
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read LZ4 decompressed data: %w", err)
	}

	return decompressed, nil
}