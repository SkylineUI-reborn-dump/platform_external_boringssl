// Copyright (c) 2017, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// inject_hash parses an archive containing a file object file. It finds a FIPS
// module inside that object, calculates its hash and replaces the default hash
// value in the object with the calculated value.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

// UninitHashValue is the default hash value that we inject into the module.
// This value need only be distinct, i.e. so that we can safely
// search-and-replace it in an object file.
var UninitHashValue = [64]byte{
	0xae, 0x2c, 0xea, 0x2a, 0xbd, 0xa6, 0xf3, 0xec, 0x97, 0x7f, 0x9b, 0xf6, 0x94, 0x9a, 0xfc, 0x83, 0x68, 0x27, 0xcb, 0xa0, 0xa0, 0x9f, 0x6b, 0x6f, 0xde, 0x52, 0xcd, 0xe2, 0xcd, 0xff, 0x31, 0x80, 0xa2, 0xd4, 0xc3, 0x66, 0x0f, 0xc2, 0x6a, 0x7b, 0xf4, 0xbe, 0x39, 0xa2, 0xd7, 0x25, 0xdb, 0x21, 0x98, 0xe9, 0xd5, 0x53, 0xbf, 0x5c, 0x32, 0x06, 0x83, 0x34, 0x0c, 0x65, 0x89, 0x52, 0xbd, 0x1f,
}

func do(outPath, oInput string, arInput string) error {
	var objectBytes []byte
	var isStatic bool
	if len(arInput) > 0 {
		// isStatic = true

		// if len(oInput) > 0 {
		// 	return fmt.Errorf("-in-archive and -in-object are mutually exclusive")
		// }

		// arFile, err := os.Open(arInput)
		// if err != nil {
		// 	return err
		// }
		// defer arFile.Close()

		// ar, err := ar.ParseAR(arFile)
		// if err != nil {
		// 	return err
		// }

		// if len(ar) != 1 {
		// 	return fmt.Errorf("expected one file in archive, but found %d", len(ar))
		// }

		// for _, contents := range ar {
		// 	objectBytes = contents
		// }
	} else if len(oInput) > 0 {
		var err error
		if objectBytes, err = ioutil.ReadFile(oInput); err != nil {
			return err
		}
		isStatic = strings.HasSuffix(oInput, ".o")
	} else {
		return fmt.Errorf("exactly one of -in-archive or -in-object is required")
	}

	object, err := elf.NewFile(bytes.NewReader(objectBytes))
	if err != nil {
		return errors.New("failed to parse object: " + err.Error())
	}

	// Find the .text and, optionally, .data sections.

	var textSection, rodataSection *elf.Section
	var textSectionIndex, rodataSectionIndex elf.SectionIndex
	for i, section := range object.Sections {
		switch section.Name {
		case ".text":
			textSectionIndex = elf.SectionIndex(i)
			textSection = section
		case ".rodata":
			rodataSectionIndex = elf.SectionIndex(i)
			rodataSection = section
		}
	}

	if textSection == nil {
		return errors.New("failed to find .text section in object")
	}

	// Find the starting and ending symbols for the module.

	var textStart, textEnd, rodataStart, rodataEnd *uint64

	symbols, err := object.Symbols()
	if err != nil {
		return errors.New("failed to parse symbols: " + err.Error())
	}

	for _, symbol := range symbols {
		var base uint64
		switch symbol.Section {
		case textSectionIndex:
			base = textSection.Addr
		case rodataSectionIndex:
			if rodataSection == nil {
				continue
			}
			base = rodataSection.Addr
		default:
			continue
		}

		if isStatic {
			// Static objects appear to have different symantics about whether symbol
			// values are relative to their section or not.
			base = 0
		} else if symbol.Value < base {
			return fmt.Errorf("symbol %q at %x, which is below base of %x", symbol.Name, symbol.Value, base)
		}

		value := symbol.Value - base
		switch symbol.Name {
		case "BORINGSSL_bcm_text_start":
			if textStart != nil {
				return errors.New("duplicate start symbol found")
			}
			textStart = &value
		case "BORINGSSL_bcm_text_end":
			if textEnd != nil {
				return errors.New("duplicate end symbol found")
			}
			textEnd = &value
		case "BORINGSSL_bcm_rodata_start":
			if rodataStart != nil {
				return errors.New("duplicate rodata start symbol found")
			}
			rodataStart = &value
		case "BORINGSSL_bcm_rodata_end":
			if rodataEnd != nil {
				return errors.New("duplicate rodata end symbol found")
			}
			rodataEnd = &value
		default:
			continue
		}
	}

	if textStart == nil || textEnd == nil {
		// return errors.New("could not find .text module boundaries in object")
		fmt.Println("could not find .text module boundaries in object, just copying")
		return ioutil.WriteFile(outPath, objectBytes, 0644) // XXX
	}

	if (rodataStart == nil) != (rodataSection == nil) {
		return errors.New("rodata start marker inconsistent with rodata section presence")
	}

	if (rodataStart != nil) != (rodataEnd != nil) {
		return errors.New("rodata marker presence inconsistent")
	}

	if max := textSection.Size; *textStart > max || *textStart > *textEnd || *textEnd > max {
		return fmt.Errorf("invalid module .text boundaries: start: %x, end: %x, max: %x", *textStart, *textEnd, max)
	}

	if rodataSection != nil {
		if max := rodataSection.Size; *rodataStart > max || *rodataStart > *rodataEnd || *rodataEnd > max {
			return fmt.Errorf("invalid module .rodata boundaries: start: %x, end: %x, max: %x", *rodataStart, *rodataEnd, max)
		}
	}

	// Extract the module from the .text section and hash it.

	text := textSection.Open()
	if _, err := text.Seek(int64(*textStart), 0); err != nil {
		return errors.New("failed to seek to module start in .text: " + err.Error())
	}
	moduleText := make([]byte, *textEnd-*textStart)
	if _, err := io.ReadFull(text, moduleText); err != nil {
		return errors.New("failed to read .text: " + err.Error())
	}

	// Maybe extract the module's read-only data too
	var moduleROData []byte
	if rodataSection != nil {
		rodata := rodataSection.Open()
		if _, err := rodata.Seek(int64(*rodataStart), 0); err != nil {
			return errors.New("failed to seek to module start in .rodata: " + err.Error())
		}
		moduleROData = make([]byte, *rodataEnd-*rodataStart)
		if _, err := io.ReadFull(rodata, moduleROData); err != nil {
			return errors.New("failed to read .rodata: " + err.Error())
		}
	}

	var zeroKey [64]byte
	mac := hmac.New(sha512.New, zeroKey[:])

	if moduleROData != nil {
		var lengthBytes [8]byte
		binary.LittleEndian.PutUint64(lengthBytes[:], uint64(len(moduleText)))
		mac.Write(lengthBytes[:])
		mac.Write(moduleText)

		binary.LittleEndian.PutUint64(lengthBytes[:], uint64(len(moduleROData)))
		mac.Write(lengthBytes[:])
		mac.Write(moduleROData)
	} else {
		mac.Write(moduleText)
	}
	calculated := mac.Sum(nil)

	// Replace the default hash value in the object with the calculated
	// value and write it out.

	offset := bytes.Index(objectBytes, UninitHashValue[:])
	if offset < 0 {
		return errors.New("did not find uninitialised hash value in object file")
	}

	if bytes.Index(objectBytes[offset+1:], UninitHashValue[:]) >= 0 {
		return errors.New("found two occurrences of uninitialised hash value in object file")
	}

	copy(objectBytes[offset:], calculated)

	return ioutil.WriteFile(outPath, objectBytes, 0644)
}

func main() {
	arInput := flag.String("in-archive", "", "Path to a .a file")
	oInput := flag.String("in-object", "", "Path to a .o file")
	outPath := flag.String("o", "", "Path to output object")

	flag.Parse()

	if err := do(*outPath, *oInput, *arInput); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
