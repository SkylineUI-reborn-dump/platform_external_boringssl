// Copyright (c) 2024, Google Inc.
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
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"boringssl.googlesource.com/boringssl/util/build"
)

// An InputTarget is a build target with build inputs that still need to be
// pregenerated. All file lists in InputTarget are interpreted with glob
// patterns as in filepath.Glob.
type InputTarget struct {
	build.Target
	// ErrData contains a list of errordata files to combine into err_data.c.
	ErrData []string `json:"err_data,omitempty"`
	// The following fields define perlasm sources for the corresponding
	// architecture.
	PerlasmAarch64 []PerlasmSource `json:"perlasm_aarch64,omitempty"`
	PerlasmArm     []PerlasmSource `json:"perlasm_arm,omitempty"`
	PerlasmX86     []PerlasmSource `json:"perlasm_x86,omitempty"`
	PerlasmX86_64  []PerlasmSource `json:"perlasm_x86_64,omitempty"`
}

type PerlasmSource struct {
	// Src the path to the input perlasm file.
	Src string `json:"src"`
	// Dst, if not empty, is base name of the destination file. If empty, this
	// is determined from Src by default. It should be overriden if a single
	// source file generates multiple functions (e.g. SHA-256 vs SHA-512) or
	// multiple architectures (e.g. the "armx" files).
	Dst string `json:"dst,omitempty"`
	// Args is a list of extra parameters to pass to the script.
	Args []string `json:"args,omitempty"`
}

// Pregenerate converts an input target to an output target. It returns the
// result alongside a list of tasks that must be run to build the referenced
// files.
func (in *InputTarget) Pregenerate(name string) (out build.Target, tasks []Task, err error) {
	// Expand wildcards.
	out.Srcs, err = glob(in.Srcs)
	if err != nil {
		return
	}
	out.Hdrs, err = glob(in.Hdrs)
	if err != nil {
		return
	}
	out.InternalHdrs, err = glob(in.InternalHdrs)
	if err != nil {
		return
	}
	out.Asm, err = glob(in.Asm)
	if err != nil {
		return
	}
	out.Nasm, err = glob(in.Nasm)
	if err != nil {
		return
	}
	out.Data, err = glob(in.Data)
	if err != nil {
		return
	}

	addTask := func(list *[]string, t Task) {
		tasks = append(tasks, t)
		*list = append(*list, t.Destination())
	}

	if len(in.ErrData) != 0 {
		var inputs []string
		inputs, err = glob(in.ErrData)
		if err != nil {
			return
		}
		addTask(&out.Srcs, &ErrDataTask{TargetName: name, Inputs: inputs})
	}

	addPerlasmTask := func(list *[]string, p *PerlasmSource, fileSuffix string, args []string) {
		dst := p.Dst
		if len(p.Dst) == 0 {
			dst = strings.TrimSuffix(path.Base(p.Src), ".pl")
		}
		dst = path.Join("gen", name, dst+fileSuffix)
		args = append(slices.Clone(args), p.Args...)
		addTask(list, &PerlasmTask{Src: p.Src, Dst: dst, Args: args})
	}

	for _, p := range in.PerlasmAarch64 {
		addPerlasmTask(&out.Asm, &p, "-apple.S", []string{"ios64"})
		addPerlasmTask(&out.Asm, &p, "-linux.S", []string{"linux64"})
		addPerlasmTask(&out.Asm, &p, "-win.S", []string{"win64"})
	}
	for _, p := range in.PerlasmArm {
		addPerlasmTask(&out.Asm, &p, "-linux.S", []string{"linux32"})
	}
	for _, p := range in.PerlasmX86 {
		addPerlasmTask(&out.Asm, &p, "-apple.S", []string{"macosx", "-fPIC"})
		addPerlasmTask(&out.Asm, &p, "-linux.S", []string{"elf", "-fPIC"})
		addPerlasmTask(&out.Nasm, &p, "-win.asm", []string{"win32n", "-fPIC"})
	}
	for _, p := range in.PerlasmX86_64 {
		addPerlasmTask(&out.Asm, &p, "-apple.S", []string{"macosx"})
		addPerlasmTask(&out.Asm, &p, "-linux.S", []string{"elf"})
		addPerlasmTask(&out.Nasm, &p, "-win.asm", []string{"nasm"})
	}

	// Re-sort the modified fields.
	slices.Sort(out.Srcs)
	slices.Sort(out.Asm)
	slices.Sort(out.Nasm)

	return
}

func glob(paths []string) ([]string, error) {
	var ret []string
	for _, path := range paths {
		if !strings.ContainsRune(path, '*') {
			ret = append(ret, path)
			continue
		}
		matches, err := filepath.Glob(path)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("glob matched no files: %q", path)
		}
		// Switch from Windows to POSIX paths.
		for _, match := range matches {
			ret = append(ret, strings.ReplaceAll(match, "\\", "/"))
		}
	}
	slices.Sort(ret)
	return ret, nil
}

func sortedKeys[K cmp.Ordered, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func writeHeader(b *bytes.Buffer, comment string) {
	fmt.Fprintf(b, "%s Copyright (c) 2024, Google Inc.\n", comment)
	fmt.Fprintf(b, "%s\n", comment)
	fmt.Fprintf(b, "%s Permission to use, copy, modify, and/or distribute this software for any\n", comment)
	fmt.Fprintf(b, "%s purpose with or without fee is hereby granted, provided that the above\n", comment)
	fmt.Fprintf(b, "%s copyright notice and this permission notice appear in all copies.\n", comment)
	fmt.Fprintf(b, "%s\n", comment)
	fmt.Fprintf(b, "%s THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES\n", comment)
	fmt.Fprintf(b, "%s WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF\n", comment)
	fmt.Fprintf(b, "%s MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY\n", comment)
	fmt.Fprintf(b, "%s SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES\n", comment)
	fmt.Fprintf(b, "%s WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION\n", comment)
	fmt.Fprintf(b, "%s OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN\n", comment)
	fmt.Fprintf(b, "%s CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.\n", comment)
	fmt.Fprintf(b, "%s\n", comment)
	fmt.Fprintf(b, "%s Generated by go ./util/pregenerate. Do not edit manually.\n", comment)
}

func buildVariablesTask(targets map[string]build.Target, dst, comment string, writeVariable func(b *bytes.Buffer, name string, val []string)) Task {
	return NewSimpleTask(dst, func() ([]byte, error) {
		var b bytes.Buffer
		writeHeader(&b, comment)

		for _, name := range sortedKeys(targets) {
			target := targets[name]
			if len(target.Srcs) != 0 {
				writeVariable(&b, name+"_sources", target.Srcs)
			}
			if len(target.Hdrs) != 0 {
				writeVariable(&b, name+"_headers", target.Hdrs)
			}
			if len(target.InternalHdrs) != 0 {
				writeVariable(&b, name+"_internal_headers", target.InternalHdrs)
			}
			if len(target.Asm) != 0 {
				writeVariable(&b, name+"_sources_asm", target.Asm)
			}
			if len(target.Nasm) != 0 {
				writeVariable(&b, name+"_sources_nasm", target.Nasm)
			}
			if len(target.Data) != 0 {
				writeVariable(&b, name+"_data", target.Data)
			}
		}

		return b.Bytes(), nil
	})
}

func writeBazelVariable(b *bytes.Buffer, name string, val []string) {
	fmt.Fprintf(b, "\n%s = [\n", name)
	for _, v := range val {
		fmt.Fprintf(b, "    %q,\n", v)
	}
	fmt.Fprintf(b, "]\n")
}

func writeCMakeVariable(b *bytes.Buffer, name string, val []string) {
	fmt.Fprintf(b, "\nset(\n")
	fmt.Fprintf(b, "  %s\n\n", strings.ToUpper(name))
	for _, v := range val {
		fmt.Fprintf(b, "  %s\n", v)
	}
	fmt.Fprintf(b, ")\n")
}

func writeMakeVariable(b *bytes.Buffer, name string, val []string) {
	fmt.Fprintf(b, "\n%s := \\\n", name)
	for i, v := range val {
		if i == len(val)-1 {
			fmt.Fprintf(b, "  %s\n", v)
		} else {
			fmt.Fprintf(b, "  %s \\\n", v)
		}
	}
}

func writeGNVariable(b *bytes.Buffer, name string, val []string) {
	fmt.Fprintf(b, "\n%s = [\n", name)
	for _, v := range val {
		fmt.Fprintf(b, "  %q,\n", v)
	}
	fmt.Fprintf(b, "]\n")
}

func jsonTask(targets map[string]build.Target, dst string) Task {
	return NewSimpleTask(dst, func() ([]byte, error) {
		return json.MarshalIndent(targets, "", "  ")
	})
}

func soongTask(targets map[string]build.Target, dst string) Task {
	return NewSimpleTask(dst, func() ([]byte, error) {
		var b bytes.Buffer
		writeHeader(&b, "//")

		writeAttribute := func(indent, name string, val []string) {
			fmt.Fprintf(&b, "%s%s: [\n", indent, name)
			for _, v := range val {
				fmt.Fprintf(&b, "%s    %q,\n", indent, v)
			}
			fmt.Fprintf(&b, "%s],\n", indent)

		}

		for _, name := range sortedKeys(targets) {
			target := targets[name]
			fmt.Fprintf(&b, "\ncc_defaults {\n")
			fmt.Fprintf(&b, "    name: %q\n", "boringssl_"+name+"_sources")
			if len(target.Srcs) != 0 {
				writeAttribute("    ", "srcs", target.Srcs)
			}
			if len(target.Data) != 0 {
				writeAttribute("    ", "data", target.Data)
			}
			if len(target.Asm) != 0 {
				fmt.Fprintf(&b, "    target: {\n")
				// Only emit asm for Linux. On Windows, BoringSSL requires NASM, which is
				// not available in AOSP. On Darwin, the assembly works fine, but it
				// conflicts with Android's FIPS build. See b/294399371.
				fmt.Fprintf(&b, "        linux: {\n")
				writeAttribute("            ", "srcs", target.Asm)
				fmt.Fprintf(&b, "        },\n")
				fmt.Fprintf(&b, "        darwin: {\n")
				fmt.Fprintf(&b, "            cflags: [\"-DOPENSSL_NO_ASM\"],\n")
				fmt.Fprintf(&b, "        },\n")
				fmt.Fprintf(&b, "        windows: {\n")
				fmt.Fprintf(&b, "            cflags: [\"-DOPENSSL_NO_ASM\"],\n")
				fmt.Fprintf(&b, "        },\n")
				fmt.Fprintf(&b, "    },\n")
			}
			fmt.Fprintf(&b, "},\n")
		}

		return b.Bytes(), nil
	})
}

func MakeBuildFiles(targets map[string]build.Target) []Task {
	// TODO(crbug.com/boringssl/542): Generate the build files for the other
	// types as well.
	return []Task{
		buildVariablesTask(targets, "gen/sources.bzl", "#", writeBazelVariable),
		buildVariablesTask(targets, "gen/sources.cmake", "#", writeCMakeVariable),
		jsonTask(targets, "gen/sources.json"),
	}
}
