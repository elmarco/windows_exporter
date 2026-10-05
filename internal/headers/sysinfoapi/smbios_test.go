// SPDX-License-Identifier: Apache-2.0
//
// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sysinfoapi

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatUUID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		raw          []byte
		smbios26Plus bool
		expected     string
	}{
		{
			name: "SMBIOS 2.6+ UUID with LE byte swap",
			// Stored as: 78 56 34 12 34 12 78 56 12 34 56 78 9a bc de f0
			// Expected:  12345678-1234-5678-1234-56789abcdef0
			raw:          []byte{0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
			smbios26Plus: true,
			expected:     "12345678-1234-5678-1234-56789abcdef0",
		},
		{
			name: "pre-2.6 UUID in network byte order",
			// All fields in big-endian (network) order.
			raw:          []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
			smbios26Plus: false,
			expected:     "12345678-1234-5678-1234-56789abcdef0",
		},
		{
			name:         "all zeros - not settable",
			raw:          make([]byte, 16),
			smbios26Plus: true,
			expected:     "",
		},
		{
			name:         "all 0xFF - not present",
			raw:          []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			smbios26Plus: true,
			expected:     "",
		},
		{
			name:         "too short",
			raw:          []byte{0x01, 0x02},
			smbios26Plus: true,
			expected:     "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, formatUUID(tc.raw, tc.smbios26Plus))
		})
	}
}

func TestExtractStrings(t *testing.T) {
	t.Parallel()

	data := []byte("QEMU\x00Standard PC\x00v1.0\x00\x00")
	result := extractStrings(data)
	require.Len(t, result, 3)
	assert.Equal(t, "QEMU", result[0])
	assert.Equal(t, "Standard PC", result[1])
	assert.Equal(t, "v1.0", result[2])
}

func TestGetStringByIndex(t *testing.T) {
	t.Parallel()

	strings := []string{"first", "second", "third"}
	assert.Empty(t, getStringByIndex(strings, 0))
	assert.Equal(t, "first", getStringByIndex(strings, 1))
	assert.Equal(t, "second", getStringByIndex(strings, 2))
	assert.Equal(t, "third", getStringByIndex(strings, 3))
	assert.Empty(t, getStringByIndex(strings, 4))
}

func TestParseSMBIOSSystemInfo(t *testing.T) {
	t.Parallel()

	// Build a minimal RSMB blob with a Type 1 structure.
	// Header: 8 bytes (rawSMBIOSData).
	header := []byte{
		0x00,                   // Used20CallingMethod
		0x03,                   // SMBIOSMajorVersion
		0x02,                   // SMBIOSMinorVersion
		0x00,                   // DMARevision
		0x00, 0x00, 0x00, 0x00, // Length (placeholder)
	}

	// Type 1 formatted area: 0x19 bytes
	type1 := make([]byte, 0x19)
	type1[0] = 1    // Type
	type1[1] = 0x19 // Length
	// Handle (2 bytes) - don't care
	type1[4] = 1 // Manufacturer string index
	type1[5] = 2 // Product Name string index
	type1[6] = 3 // Version string index
	type1[7] = 4 // Serial Number string index

	// UUID at offset 0x08: 16 bytes
	// Store 12345678-1234-5678-9abc-def012345678 in SMBIOS LE format
	copy(type1[0x08:], []byte{0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78})

	// Strings area
	strings := []byte("QEMU\x00Standard PC (Q35 + ICH9, 2009)\x00pc-q35-9.2\x00SN-12345\x00\x00")

	// Combine
	tableData := slices.Concat(type1, strings)
	tableLen := len(tableData)

	// Fill in length in header
	header[4] = byte(tableLen)
	header[5] = byte(tableLen >> 8)
	header[6] = byte(tableLen >> 16)
	header[7] = byte(tableLen >> 24)

	data := slices.Concat(header, tableData)

	info, err := parseSMBIOSSystemInfo(data)
	require.NoError(t, err)
	assert.Equal(t, "QEMU", info.Manufacturer)
	assert.Equal(t, "Standard PC (Q35 + ICH9, 2009)", info.ProductName)
	assert.Equal(t, "pc-q35-9.2", info.Version)
	assert.Equal(t, "SN-12345", info.SerialNumber)
	assert.Equal(t, "12345678-1234-5678-9abc-def012345678", info.UUID)
}

func TestParseSMBIOSSystemInfoPre26(t *testing.T) {
	t.Parallel()

	// SMBIOS 2.5 header: UUID bytes in network (big-endian) order.
	header := []byte{
		0x00,                   // Used20CallingMethod
		0x02,                   // SMBIOSMajorVersion = 2
		0x05,                   // SMBIOSMinorVersion = 5 (pre-2.6)
		0x00,                   // DMARevision
		0x00, 0x00, 0x00, 0x00, // Length (placeholder)
	}

	type1 := make([]byte, 0x19)
	type1[0] = 1    // Type
	type1[1] = 0x19 // Length
	type1[4] = 1    // Manufacturer string index
	type1[5] = 2    // Product Name string index
	type1[6] = 3    // Version string index
	type1[7] = 4    // Serial Number string index

	// UUID in network byte order: 12345678-1234-5678-9abc-def012345678
	copy(type1[0x08:], []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78})

	strs := []byte("QEMU\x00Standard PC\x00v1.0\x00SN-001\x00\x00")

	tableData := slices.Concat(type1, strs)
	tableLen := len(tableData)
	header[4] = byte(tableLen)
	header[5] = byte(tableLen >> 8)
	header[6] = byte(tableLen >> 16)
	header[7] = byte(tableLen >> 24)

	data := slices.Concat(header, tableData)

	info, err := parseSMBIOSSystemInfo(data)
	require.NoError(t, err)
	assert.Equal(t, "12345678-1234-5678-9abc-def012345678", info.UUID)
	assert.Equal(t, "QEMU", info.Manufacturer)
}

func TestParseSMBIOSSystemInfoSMBIOS20(t *testing.T) {
	t.Parallel()

	// SMBIOS 2.0 Type 1 structure: only 8 bytes (no UUID field).
	header := []byte{
		0x00,                   // Used20CallingMethod
		0x02,                   // SMBIOSMajorVersion = 2
		0x00,                   // SMBIOSMinorVersion = 0
		0x00,                   // DMARevision
		0x00, 0x00, 0x00, 0x00, // Length (placeholder)
	}

	type1 := make([]byte, 0x08)
	type1[0] = 1    // Type
	type1[1] = 0x08 // Length (8 bytes, no UUID)
	type1[4] = 1    // Manufacturer string index
	type1[5] = 2    // Product Name string index
	type1[6] = 3    // Version string index
	type1[7] = 4    // Serial Number string index

	strs := []byte("OldBIOS\x00Legacy PC\x00v0.1\x00SN-OLD\x00\x00")

	tableData := slices.Concat(type1, strs)
	tableLen := len(tableData)
	header[4] = byte(tableLen)
	header[5] = byte(tableLen >> 8)
	header[6] = byte(tableLen >> 16)
	header[7] = byte(tableLen >> 24)

	data := slices.Concat(header, tableData)

	info, err := parseSMBIOSSystemInfo(data)
	require.NoError(t, err)
	assert.Equal(t, "OldBIOS", info.Manufacturer)
	assert.Equal(t, "Legacy PC", info.ProductName)
	assert.Equal(t, "v0.1", info.Version)
	assert.Equal(t, "SN-OLD", info.SerialNumber)
	assert.Empty(t, info.UUID, "UUID should be empty for 8-byte SMBIOS 2.0 Type 1 structures")
}

func TestParseSMBIOSSystemInfoUnterminatedStrings(t *testing.T) {
	t.Parallel()

	// Build a Type 1 structure whose string area lacks the double-NUL terminator.
	header := []byte{
		0x00,                   // Used20CallingMethod
		0x03,                   // SMBIOSMajorVersion
		0x02,                   // SMBIOSMinorVersion
		0x00,                   // DMARevision
		0x00, 0x00, 0x00, 0x00, // Length (placeholder)
	}

	type1 := make([]byte, 0x19)
	type1[0] = 1    // Type
	type1[1] = 0x19 // Length
	type1[4] = 1    // Manufacturer string index

	// String area with only a single NUL (missing the terminating double-NUL).
	strs := []byte("QEMU\x00")

	tableData := slices.Concat(type1, strs)
	tableLen := len(tableData)
	header[4] = byte(tableLen)
	header[5] = byte(tableLen >> 8)
	header[6] = byte(tableLen >> 16)
	header[7] = byte(tableLen >> 24)

	data := slices.Concat(header, tableData)

	_, err := parseSMBIOSSystemInfo(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not properly terminated")
}
