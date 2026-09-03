package rompatcher

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ROMs and third-party patches are intentionally not redistributed.
func TestOptionalRealWorldCorpus(t *testing.T) {
	type corpusCase struct {
		name, rom, patch       string
		romCRC, patchCRC, want uint32
	}
	cases := []corpusCase{
		{"IPS SML2 DX", "Super Mario Land 2 - 6 Golden Coins (USA, Europe).gb", "SML2DXv181.ips", 0xd5ec24e4, 0x0b742316, 0xf0799017},
		{"BPS Samurai Kid", "Samurai Kid (Japan).gbc", "samurai_kid_en_v1.bps", 0x44a9ddfb, 0x2144df1c, 0xed238edb},
		{"UPS Mother 3", "Mother 3 (Japan).gba", "mother3.ups", 0x42ac9cb9, 0x2144df1c, 0x8a3bc5a8},
		{"APS GBA FFTAX", "Final Fantasy Tactics Advance (USA).gba", "FFTA_X_1.0.3.1.aps", 0x5645e56c, 0x77e5f2ae, 0x49a5539a},
		{"EBP Mother Rebound", "EarthBound (USA).sfc", "Mother_Rebound.ebp", 0xdc9bb451, 0x271719e1, 0x5065b02f},
		{"BDF Rosy Retrospection", "Tetris (World) (Rev 1).gb", "rosy_retrospection.bdf", 0x46df91ad, 0xcc61564a, 0x3d400209},
		{"VCDIFF NSMB Infusion", "New Super Mario Bros. (USA, Australia).nds", "nsmb_infusion10a.xdelta", 0x0197576a, 0xa211f97c, 0x9cecd976},
	}
	root := filepath.Join("testdata", "corpus")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rom, err := os.ReadFile(filepath.Join(root, "roms", tc.rom))
			if errors.Is(err, os.ErrNotExist) {
				t.Skip("optional corpus ROM not present")
			}
			if err != nil {
				t.Fatal(err)
			}
			patch, err := os.ReadFile(filepath.Join(root, "patches", tc.patch))
			if errors.Is(err, os.ErrNotExist) {
				t.Skip("optional corpus patch not present")
			}
			if err != nil {
				t.Fatal(err)
			}
			if CRC32(rom) != tc.romCRC || CRC32(patch) != tc.patchCRC {
				t.Fatal("fixture checksum mismatch")
			}
			out, err := Apply(rom, patch, ApplyOptions{Validate: true, SourceName: tc.rom})
			if err != nil {
				t.Fatal(err)
			}
			if got := CRC32(out); got != tc.want {
				t.Fatalf("output CRC32 %08x, want %08x", got, tc.want)
			}
		})
	}
}
