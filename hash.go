package rompatcher

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"hash/adler32"
	"hash/crc32"
	"io"
)

type HashInfo struct {
	Size  int64  `json:"size"`
	CRC32 string `json:"crc32"`
	MD5   string `json:"md5"`
	SHA1  string `json:"sha1"`
}

func CRC32(data []byte) uint32   { return crc32.ChecksumIEEE(data) }
func Adler32(data []byte) uint32 { return adler32.Checksum(data) }

// CRC16 returns CRC-16/CCITT-FALSE, used by APS (GBA).
func CRC16(data []byte) uint16 {
	crc := uint16(0xffff)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for bit := 0; bit < 8; bit++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func MD5(data []byte) string {
	s := md5.Sum(data)
	return hex.EncodeToString(s[:])
}

func SHA1(data []byte) string {
	s := sha1.Sum(data)
	return hex.EncodeToString(s[:])
}

func crc32Cancelable(data []byte, opts ApplyOptions) (uint32, error) {
	h := crc32.NewIEEE()
	for offset := 0; offset < len(data); {
		if err := checkCanceled(opts); err != nil {
			return 0, err
		}
		end := offset + fileChunkSize
		if end > len(data) {
			end = len(data)
		}
		_, _ = h.Write(data[offset:end])
		offset = end
	}
	return h.Sum32(), checkCanceled(opts)
}

func adler32Cancelable(data []byte, opts ApplyOptions) (uint32, error) {
	h := adler32.New()
	for offset := 0; offset < len(data); {
		if err := checkCanceled(opts); err != nil {
			return 0, err
		}
		end := offset + fileChunkSize
		if end > len(data) {
			end = len(data)
		}
		_, _ = h.Write(data[offset:end])
		offset = end
	}
	return h.Sum32(), checkCanceled(opts)
}

func md5Cancelable(data []byte, opts ApplyOptions) (string, error) {
	h := md5.New()
	for offset := 0; offset < len(data); {
		if err := checkCanceled(opts); err != nil {
			return "", err
		}
		end := offset + fileChunkSize
		if end > len(data) {
			end = len(data)
		}
		_, _ = h.Write(data[offset:end])
		offset = end
	}
	return hex.EncodeToString(h.Sum(nil)), checkCanceled(opts)
}

func HashBytes(data []byte) HashInfo {
	return HashInfo{Size: int64(len(data)), CRC32: hex.EncodeToString(uint32Bytes(CRC32(data))), MD5: MD5(data), SHA1: SHA1(data)}
}

func uint32Bytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// HashReader calculates all supported hashes in one read pass.
func HashReader(ctx context.Context, r io.Reader) (HashInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	crc, md, sha := crc32.NewIEEE(), md5.New(), sha1.New()
	buf := make([]byte, fileChunkSize)
	var size int64
	for {
		select {
		case <-ctx.Done():
			return HashInfo{}, ctx.Err()
		default:
		}
		n, err := r.Read(buf)
		if n > 0 {
			_, _ = crc.Write(buf[:n])
			_, _ = md.Write(buf[:n])
			_, _ = sha.Write(buf[:n])
			size += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return HashInfo{}, err
		}
		if n == 0 {
			return HashInfo{}, io.ErrNoProgress
		}
	}
	return HashInfo{Size: size, CRC32: hex.EncodeToString(crc.Sum(nil)), MD5: hex.EncodeToString(md.Sum(nil)), SHA1: hex.EncodeToString(sha.Sum(nil))}, nil
}
