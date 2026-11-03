package main

// The 32-bit Windows installer heuristic treats names containing "patch" as
// requiring elevation unless an embedded manifest declares execution privileges.
// Commit the generated resource so ordinary builds need only Go.
// Regeneration requires GNU windres on PATH; run go generate in this directory.
//go:generate windres --target=pe-i386 --input=manifest.rc --output=manifest_windows_386.syso --output-format=coff
