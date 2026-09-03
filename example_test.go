package rompatcher_test

import (
	"bytes"
	"context"
	"fmt"
	"os"

	rompatcher "github.com/olsonb97/RomPatcher.go"
)

func ExampleApply() {
	original := []byte("original data")
	modified := []byte("patched! data")
	patch, _ := rompatcher.Create(original, modified, rompatcher.FormatBPS, nil)
	encoded, _ := patch.MarshalBinary()

	output, _ := rompatcher.Apply(original, encoded, rompatcher.ApplyOptions{Validate: true})
	fmt.Println(string(output))
	// Output: patched! data
}

func ExampleCreateReaderAt() {
	original := []byte("before")
	modified := []byte("after!")
	var encoded bytes.Buffer

	size, _ := rompatcher.CreateReaderAt(
		context.Background(),
		bytes.NewReader(original), int64(len(original)),
		bytes.NewReader(modified), int64(len(modified)),
		&encoded, rompatcher.FormatIPS, nil,
	)
	fmt.Println(size == int64(encoded.Len()))
	// Output: true
}

func ExampleApplyReaderAt() {
	original := []byte("before")
	modified := []byte("after!")
	patch, _ := rompatcher.Create(original, modified, rompatcher.FormatBPS, nil)
	encoded, _ := patch.MarshalBinary()
	output, _ := os.CreateTemp("", "rompatcher-example-*")
	defer os.Remove(output.Name())
	defer output.Close()

	size, _ := rompatcher.ApplyReaderAt(
		context.Background(),
		bytes.NewReader(original), int64(len(original)),
		bytes.NewReader(encoded), int64(len(encoded)),
		output, rompatcher.ApplyOptions{Validate: true},
	)
	data := make([]byte, size)
	_, _ = output.ReadAt(data, 0)
	fmt.Println(string(data))
	// Output: after!
}
