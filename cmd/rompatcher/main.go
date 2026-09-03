package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	rompatcher "github.com/olsonb97/RomPatcher.go"
)

var version = "dev"

func usage() {
	fmt.Fprintln(os.Stderr, "usage: rompatcher COMMAND [options]\n\ncommands:\n  apply     apply one or more patches in order\n  chain     alias for apply\n  create    create a patch from two files\n  inspect   show patch metadata and requirements\n  archive   list selectable ZIP entries\n  hash      calculate file hashes\n  batch     run jobs from a JSON manifest\n  version   print the program version\n\nrun 'rompatcher COMMAND --help' for examples")
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "apply", "patch":
		err = apply(ctx, os.Args[2:])
	case "chain":
		err = chain(ctx, os.Args[2:])
	case "batch":
		err = batch(ctx, os.Args[2:])
	case "create":
		err = create(ctx, os.Args[2:])
	case "inspect":
		err = inspect(os.Args[2:])
	case "archive":
		err = archive(os.Args[2:])
	case "hash":
		err = hashFile(ctx, os.Args[2:])
	case "version", "-V", "--version":
		fmt.Println("rompatcher", version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if requestedJSON(os.Args[2:]) {
			_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"status": "error", "error": err.Error()})
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func requestedJSON(args []string) bool {
	for _, arg := range args {
		if arg == "--json" || arg == "-json" || arg == "-j" {
			return true
		}
		for _, prefix := range []string{"--json=", "-json=", "-j="} {
			if value, found := strings.CutPrefix(arg, prefix); found {
				enabled, err := strconv.ParseBool(value)
				if err == nil && enabled {
					return true
				}
			}
		}
	}
	return false
}

type applyFlags struct {
	validate, remove, add, fix, dryRun, jsonOutput, progress bool
	output, sourceEntry                                      string
	maxOutput                                                uint64
	patchEntries                                             stringList
}

func addApplyFlags(f *flag.FlagSet) *applyFlags {
	o := &applyFlags{}
	f.BoolVar(&o.validate, "validate", false, "validate source and target checksums")
	f.BoolVar(&o.validate, "v", false, "alias for --validate")
	f.BoolVar(&o.remove, "remove-header", false, "temporarily remove a recognized ROM header")
	f.BoolVar(&o.add, "add-header", false, "temporarily add a recognized ROM header")
	f.BoolVar(&o.fix, "fix-checksum", false, "fix a recognized internal ROM checksum")
	f.BoolVar(&o.dryRun, "dry-run", false, "validate and calculate output details without writing")
	f.BoolVar(&o.dryRun, "n", false, "alias for --dry-run")
	f.BoolVar(&o.jsonOutput, "json", false, "write machine-readable JSON")
	f.BoolVar(&o.jsonOutput, "j", false, "alias for --json")
	f.BoolVar(&o.progress, "progress", false, "write progress updates to stderr")
	f.BoolVar(&o.progress, "p", false, "alias for --progress")
	f.Uint64Var(&o.maxOutput, "max-output", 0, "maximum output size in bytes")
	f.Uint64Var(&o.maxOutput, "m", 0, "alias for --max-output")
	f.StringVar(&o.output, "output", "", "output file; use - for stdout")
	f.StringVar(&o.output, "o", "", "alias for --output")
	f.StringVar(&o.sourceEntry, "source-entry", "", "source entry inside a ZIP")
	f.StringVar(&o.sourceEntry, "s", "", "alias for --source-entry")
	f.Var(&o.patchEntries, "patch-entry", "patch entry inside a ZIP; repeat for ZIP patches in order")
	f.Var(&o.patchEntries, "e", "alias for --patch-entry")
	return o
}

func (o *applyFlags) options(ctx context.Context, sourceName string) rompatcher.ApplyOptions {
	return rompatcher.ApplyOptions{
		Context: ctx, Validate: o.validate, RemoveHeader: o.remove, AddHeader: o.add,
		FixChecksum: o.fix, SourceName: sourceName, MaxOutputSize: o.maxOutput,
		Progress: progressPrinter(o.progress),
	}
}

func progressPrinter(enabled bool) func(rompatcher.Progress) {
	if !enabled {
		return nil
	}
	return func(progress rompatcher.Progress) {
		if progress.Total > 0 {
			fmt.Fprintf(os.Stderr, "\r%s %d/%d", progress.Phase, progress.Completed, progress.Total)
		} else {
			fmt.Fprintf(os.Stderr, "\r%s %d", progress.Phase, progress.Completed)
		}
		if progress.Phase == "complete" {
			fmt.Fprintln(os.Stderr)
		}
	}
}

func apply(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("apply", flag.ContinueOnError)
	o := addApplyFlags(f)
	f.Usage = func() {
		fmt.Fprintln(f.Output(), `usage: rompatcher apply [options] SOURCE PATCH [PATCH...]

examples:
  rompatcher apply game.sfc translation.bps
  rompatcher apply game.sfc base.bps fix.ips -o final.sfc
  rompatcher apply games.zip patch.bps -s "region/game.sfc" -o game.sfc

options:
  -o, --output FILE        output file; use - for stdout
  -v, --validate           validate source and target checksums
  -n, --dry-run            inspect and validate without writing
  -j, --json               emit machine-readable JSON
  -p, --progress           show progress on stderr
  -m, --max-output BYTES   reject larger outputs
  -s, --source-entry NAME  source entry inside a ZIP
  -e, --patch-entry NAME   patch entry inside a ZIP; repeat for ZIP patches in order
      --add-header         temporarily add a recognized ROM header
      --remove-header      temporarily remove a recognized ROM header
      --fix-checksum       repair a recognized internal ROM checksum`)
	}
	if err := parseInterspersed(f, args); err != nil {
		return err
	}
	if f.NArg() < 2 {
		return errors.New("apply requires SOURCE PATCH [PATCH...]")
	}
	if o.remove && o.add {
		return errors.New("--remove-header and --add-header cannot be used together")
	}
	sourcePath, patchPaths := f.Arg(0), f.Args()[1:]
	stdinCount := 0
	if sourcePath == "-" {
		stdinCount++
	}
	for _, path := range patchPaths {
		if path == "-" {
			stdinCount++
		}
	}
	if stdinCount > 1 {
		return errors.New("only one input may use stdin")
	}
	patchEntries, err := assignPatchEntries(patchPaths, o.patchEntries)
	if err != nil {
		return err
	}

	outputPath := o.output
	fileBacked := sourcePath != "-" && outputPath != "-"
	for _, path := range patchPaths {
		fileBacked = fileBacked && path != "-"
	}
	if fileBacked && !o.dryRun {
		materialSource, sourceName, cleanSource, err := materializeInput(sourcePath, o.sourceEntry, rompatcher.InputSource, 0)
		if err != nil {
			return fmt.Errorf("source: %w", err)
		}
		defer cleanSource()
		if outputPath == "" {
			outputPath = defaultOutputPath(sourcePath, sourceName)
		}
		materialPatches := make([]string, 0, len(patchPaths))
		for index, patchPath := range patchPaths {
			materialPatch, _, cleanPatch, err := materializeInput(patchPath, patchEntries[index], rompatcher.InputPatch, 0)
			if err != nil {
				return fmt.Errorf("patch %d: %w", index+1, err)
			}
			defer cleanPatch()
			materialPatches = append(materialPatches, materialPatch)
		}
		opts := o.options(ctx, sourceName)
		if len(materialPatches) == 1 {
			if err := rompatcher.ApplyFileContext(ctx, materialSource, materialPatches[0], outputPath, opts); err != nil {
				return err
			}
			return emit(o.jsonOutput, map[string]any{"status": "ok", "output": outputPath}, "patched ROM written to "+outputPath)
		}
		result, err := rompatcher.ApplyFileChainContext(ctx, materialSource, materialPatches, outputPath, opts)
		if err != nil {
			return err
		}
		return emit(o.jsonOutput, map[string]any{"status": "ok", "output": outputPath, "steps": result.Steps}, "patched ROM written to "+outputPath)
	}
	if outputPath == "" && sourcePath == "-" && !o.dryRun {
		return errors.New("stdin sources require -o/--output")
	}
	source, sourceName, err := readInput(sourcePath, o.sourceEntry, rompatcher.InputSource, 0)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if outputPath == "" {
		outputPath = defaultOutputPath(sourcePath, sourceName)
	}
	patches := make([][]byte, 0, len(patchPaths))
	for i, path := range patchPaths {
		patchData, _, err := readInput(path, patchEntries[i], rompatcher.InputPatch, 256<<20)
		if err != nil {
			return fmt.Errorf("patch %d: %w", i+1, err)
		}
		patches = append(patches, patchData)
	}
	opts := o.options(ctx, sourceName)
	if o.dryRun {
		if len(patches) == 1 {
			result, err := rompatcher.DryRun(source, patches[0], opts)
			if err != nil {
				return err
			}
			return emit(o.jsonOutput, result, fmt.Sprintf("dry run succeeded: %s, %d bytes", result.Inspection.Format, *result.Output.Size))
		}
		result, err := rompatcher.ApplyChain(source, patches, opts)
		if err != nil {
			return err
		}
		return emit(o.jsonOutput, result, fmt.Sprintf("chain dry run succeeded: %d patches", len(result.Steps)))
	}
	var out []byte
	var details any
	if len(patches) == 1 {
		out, err = rompatcher.Apply(source, patches[0], opts)
	} else {
		result, chainErr := rompatcher.ApplyChain(source, patches, opts)
		err, out = chainErr, result.Output
		details = map[string]any{"status": "ok", "output": outputPath, "steps": result.Steps}
	}
	if err != nil {
		return err
	}
	if len(patches) == 1 {
		details = map[string]any{"status": "ok", "output": outputPath, "size": len(out), "crc32": fmt.Sprintf("%08x", rompatcher.CRC32(out))}
	}
	if err := writeOutput(outputPath, out); err != nil {
		return err
	}
	w := io.Writer(os.Stdout)
	if outputPath == "-" {
		w = os.Stderr
	}
	return emitTo(o.jsonOutput, w, details, "patched ROM written to "+outputPath)
}

func chain(ctx context.Context, args []string) error {
	return apply(ctx, args)
}

type batchPatch struct {
	Path  string `json:"path"`
	Entry string `json:"entry,omitempty"`
}
type batchJob struct {
	Source       string       `json:"source"`
	SourceEntry  string       `json:"sourceEntry,omitempty"`
	Patches      []batchPatch `json:"patches"`
	Output       string       `json:"output"`
	Validate     bool         `json:"validate,omitempty"`
	RemoveHeader bool         `json:"removeHeader,omitempty"`
	AddHeader    bool         `json:"addHeader,omitempty"`
	FixChecksum  bool         `json:"fixChecksum,omitempty"`
	MaxOutput    uint64       `json:"maxOutput,omitempty"`
}
type batchManifest struct {
	Jobs []batchJob `json:"jobs"`
}

func batch(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("batch", flag.ContinueOnError)
	jsonOutput := f.Bool("json", false, "write machine-readable JSON")
	f.BoolVar(jsonOutput, "j", false, "alias for --json")
	dryRun := f.Bool("dry-run", false, "run without writing outputs")
	f.BoolVar(dryRun, "n", false, "alias for --dry-run")
	f.Usage = func() {
		fmt.Fprintln(f.Output(), "usage: rompatcher batch [options] MANIFEST.json\n\noptions:\n  -n, --dry-run  run without writing outputs\n  -j, --json     emit machine-readable JSON")
	}
	if err := parseInterspersed(f, args); err != nil {
		return err
	}
	if f.NArg() != 1 {
		return errors.New("batch requires MANIFEST.json")
	}
	b, err := os.ReadFile(f.Arg(0))
	if err != nil {
		return err
	}
	var manifest batchManifest
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("batch manifest contains multiple JSON values")
		}
		return err
	}
	results := make([]rompatcher.ChainResult, 0, len(manifest.Jobs))
	for index, job := range manifest.Jobs {
		if job.Source == "" || len(job.Patches) == 0 || !*dryRun && job.Output == "" {
			return fmt.Errorf("job %d is incomplete", index+1)
		}
		if job.RemoveHeader && job.AddHeader {
			return fmt.Errorf("job %d: removeHeader and addHeader cannot both be enabled", index+1)
		}
		if !*dryRun {
			result, err := func() (rompatcher.ChainResult, error) {
				sourcePath, sourceName, cleanSource, err := materializeInput(job.Source, job.SourceEntry, rompatcher.InputSource, 0)
				if err != nil {
					return rompatcher.ChainResult{}, fmt.Errorf("source: %w", err)
				}
				defer cleanSource()
				patchPaths := make([]string, 0, len(job.Patches))
				cleanups := make([]func(), 0, len(job.Patches))
				defer func() {
					for _, cleanup := range cleanups {
						cleanup()
					}
				}()
				for patchIndex, item := range job.Patches {
					path, _, cleanup, err := materializeInput(item.Path, item.Entry, rompatcher.InputPatch, 0)
					if err != nil {
						return rompatcher.ChainResult{}, fmt.Errorf("patch %d: %w", patchIndex+1, err)
					}
					patchPaths = append(patchPaths, path)
					cleanups = append(cleanups, cleanup)
				}
				return rompatcher.ApplyFileChainContext(ctx, sourcePath, patchPaths, job.Output, rompatcher.ApplyOptions{
					Context: ctx, Validate: job.Validate, RemoveHeader: job.RemoveHeader,
					AddHeader: job.AddHeader, FixChecksum: job.FixChecksum,
					SourceName: sourceName, MaxOutputSize: job.MaxOutput,
				})
			}()
			if err != nil {
				return fmt.Errorf("job %d: %w", index+1, err)
			}
			results = append(results, result)
			continue
		}
		source, sourceName, err := readInput(job.Source, job.SourceEntry, rompatcher.InputSource, 0)
		if err != nil {
			return fmt.Errorf("job %d source: %w", index+1, err)
		}
		patches := make([][]byte, 0, len(job.Patches))
		for _, item := range job.Patches {
			data, _, err := readInput(item.Path, item.Entry, rompatcher.InputPatch, 256<<20)
			if err != nil {
				return fmt.Errorf("job %d patch: %w", index+1, err)
			}
			patches = append(patches, data)
		}
		result, err := rompatcher.ApplyChain(source, patches, rompatcher.ApplyOptions{
			Context: ctx, Validate: job.Validate, RemoveHeader: job.RemoveHeader,
			AddHeader: job.AddHeader, FixChecksum: job.FixChecksum,
			SourceName: sourceName, MaxOutputSize: job.MaxOutput,
		})
		if err != nil {
			return fmt.Errorf("job %d: %w", index+1, err)
		}
		// The output bytes are intentionally excluded from JSON. Release each
		// completed job before processing the next one instead of retaining all
		// batch outputs in memory.
		result.Output = nil
		results = append(results, result)
	}
	return emit(*jsonOutput, map[string]any{"status": "ok", "jobs": results}, fmt.Sprintf("completed %d batch jobs", len(results)))
}

func create(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("create", flag.ContinueOnError)
	format := f.String("format", "ips", "patch format: ips, ips32, ebp, ups, bps, aps, ppf, rup")
	f.StringVar(format, "f", "ips", "alias for --format")
	description := f.String("description", "", "patch description or metadata")
	f.StringVar(description, "d", "", "alias for --description")
	author := f.String("author", "", "patch author (EBP)")
	f.StringVar(author, "a", "", "alias for --author")
	title := f.String("title", "", "patch title (EBP)")
	f.StringVar(title, "t", "", "alias for --title")
	jsonOutput := f.Bool("json", false, "write machine-readable JSON")
	f.BoolVar(jsonOutput, "j", false, "alias for --json")
	progress := f.Bool("progress", false, "write progress updates to stderr")
	f.BoolVar(progress, "p", false, "alias for --progress")
	maxPatch := f.Uint64("max-patch", 0, "maximum patch size in bytes")
	f.Uint64Var(maxPatch, "m", 0, "alias for --max-patch")
	delta := f.Bool("delta", false, "use memory-intensive BPS delta matching")
	outputFlag := f.String("output", "", "output patch; use - for stdout")
	f.StringVar(outputFlag, "o", "", "alias for --output")
	originalEntry := f.String("original-entry", "", "original entry inside a ZIP")
	modifiedEntry := f.String("modified-entry", "", "modified entry inside a ZIP")
	f.Usage = func() {
		fmt.Fprintln(f.Output(), `usage: rompatcher create [options] ORIGINAL MODIFIED

example:
  rompatcher create original.sfc modified.sfc -f bps -o translation.bps

options:
  -f, --format FORMAT       ips, ips32, ebp, ups, bps, aps, ppf, or rup
  -o, --output FILE         output patch; use - for stdout
  -d, --description TEXT    patch description or metadata
  -a, --author NAME         EBP author
  -t, --title TITLE         EBP title
  -j, --json                emit machine-readable JSON
  -p, --progress            show progress on stderr
  -m, --max-patch BYTES     reject larger patches
      --delta               use memory-intensive BPS delta matching
      --original-entry NAME original entry inside a ZIP
      --modified-entry NAME modified entry inside a ZIP`)
	}
	if err := parseInterspersed(f, args); err != nil {
		return err
	}
	if f.NArg() != 2 {
		return errors.New("create requires ORIGINAL MODIFIED")
	}
	if f.Arg(0) == "-" && f.Arg(1) == "-" {
		return errors.New("original and modified cannot both use stdin")
	}
	formatName := strings.ToLower(strings.TrimSpace(*format))
	if *delta && formatName != "bps" {
		return errors.New("--delta is only valid with BPS creation")
	}
	if formatName != "ebp" && (*author != "" || *title != "") {
		return errors.New("--author and --title are only valid with EBP creation")
	}
	opts := &rompatcher.CreateOptions{
		Context: ctx, Description: *description, BPSDelta: *delta,
		MaxPatchSize: *maxPatch, Progress: progressPrinter(*progress),
	}
	if formatName == "ebp" {
		opts.Metadata = map[string]string{}
		if *description != "" {
			opts.Metadata["Description"] = *description
		}
		if *author != "" {
			opts.Metadata["Author"] = *author
		}
		if *title != "" {
			opts.Metadata["Title"] = *title
		}
	}
	if f.Arg(0) != "-" && f.Arg(1) != "-" && *outputFlag != "-" {
		originalPath, sourceName, cleanOriginal, err := materializeInput(f.Arg(0), *originalEntry, rompatcher.InputSource, 0)
		if err != nil {
			return err
		}
		defer cleanOriginal()
		modifiedPath, modifiedName, cleanModified, err := materializeInput(f.Arg(1), *modifiedEntry, rompatcher.InputSource, 0)
		if err != nil {
			return err
		}
		defer cleanModified()
		opts.SourceName = sourceName
		output := *outputFlag
		if output == "" {
			ext := filepath.Ext(modifiedName)
			output = strings.TrimSuffix(filepath.Base(modifiedName), ext) + "." + formatName
			if !isZIP(f.Arg(1)) {
				output = filepath.Join(filepath.Dir(f.Arg(1)), output)
			}
		}
		if err := rompatcher.CreateFileContext(ctx, originalPath, modifiedPath, output, rompatcher.Format(formatName), opts); err != nil {
			return err
		}
		info, err := os.Stat(output)
		if err != nil {
			return err
		}
		return emit(*jsonOutput, map[string]any{"status": "ok", "output": output, "format": formatName, "size": info.Size()}, "patch written to "+output)
	}
	original, sourceName, err := readInput(f.Arg(0), *originalEntry, rompatcher.InputSource, 0)
	if err != nil {
		return err
	}
	modified, modifiedName, err := readInput(f.Arg(1), *modifiedEntry, rompatcher.InputSource, 0)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	opts.SourceName = sourceName
	p, err := rompatcher.Create(original, modified, rompatcher.Format(formatName), opts)
	if err != nil {
		return err
	}
	data, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	output := *outputFlag
	if output == "" {
		if f.Arg(1) == "-" {
			output = "-"
		} else {
			ext := filepath.Ext(modifiedName)
			output = strings.TrimSuffix(filepath.Base(modifiedName), ext) + "." + formatName
			if !isZIP(f.Arg(1)) {
				output = filepath.Join(filepath.Dir(f.Arg(1)), output)
			}
		}
	}
	if err := writeOutput(output, data); err != nil {
		return err
	}
	w := io.Writer(os.Stdout)
	if output == "-" {
		w = os.Stderr
	}
	return emitTo(*jsonOutput, w, map[string]any{"status": "ok", "output": output, "format": p.Format(), "size": len(data)}, "patch written to "+output)
}

func inspect(args []string) error {
	f := flag.NewFlagSet("inspect", flag.ContinueOnError)
	jsonOutput := f.Bool("json", false, "write machine-readable JSON")
	f.BoolVar(jsonOutput, "j", false, "alias for --json")
	entry := f.String("entry", "", "patch entry inside a ZIP")
	f.StringVar(entry, "e", "", "alias for --entry")
	f.Usage = func() {
		fmt.Fprintln(f.Output(), "usage: rompatcher inspect [options] PATCH\n\noptions:\n  -e, --entry NAME  patch entry inside a ZIP\n  -j, --json        emit machine-readable JSON")
	}
	if err := parseInterspersed(f, args); err != nil {
		return err
	}
	if f.NArg() != 1 {
		return errors.New("inspect requires PATCH")
	}
	data, _, err := readInput(f.Arg(0), *entry, rompatcher.InputPatch, 256<<20)
	if err != nil {
		return err
	}
	i, err := rompatcher.Inspect(data)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return emit(true, i, "")
	}
	fmt.Println("format:", i.Format)
	if i.Source.Size != nil {
		fmt.Println("source size:", *i.Source.Size)
	}
	if i.Target.Size != nil {
		fmt.Println("target size:", *i.Target.Size)
	}
	if len(i.Source.Hashes) > 0 {
		fmt.Println("source hashes:", i.Source.Hashes)
	}
	if len(i.Target.Hashes) > 0 {
		fmt.Println("target hashes:", i.Target.Hashes)
	}
	if i.Description != "" {
		fmt.Println("description:", strconv.QuoteToGraphic(i.Description))
	}
	if i.RecordCountKnown {
		fmt.Println("records:", i.RecordCount)
	} else {
		fmt.Println("records: unknown until application")
	}
	fmt.Println("reversible:", i.Reversible)
	return nil
}

func archive(args []string) error {
	f := flag.NewFlagSet("archive", flag.ContinueOnError)
	jsonOutput := f.Bool("json", false, "write machine-readable JSON")
	f.BoolVar(jsonOutput, "j", false, "alias for --json")
	f.Usage = func() {
		fmt.Fprintln(f.Output(), "usage: rompatcher archive [options] FILE.zip\n\noptions:\n  -j, --json  emit machine-readable JSON")
	}
	if err := parseInterspersed(f, args); err != nil {
		return err
	}
	if f.NArg() != 1 {
		return errors.New("archive requires FILE.zip")
	}
	entries, err := rompatcher.ListZIP(f.Arg(0))
	if err != nil {
		return err
	}
	if *jsonOutput {
		return emit(true, entries, "")
	}
	for _, e := range entries {
		kinds := ""
		if e.SourceCandidate {
			kinds += " source"
		}
		if e.PatchCandidate {
			kinds += " patch"
		}
		fmt.Printf("%10d  %-12s %s\n", e.Size, strings.TrimSpace(kinds), strconv.QuoteToGraphic(e.Name))
	}
	return nil
}

func hashFile(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("hash", flag.ContinueOnError)
	jsonOutput := f.Bool("json", false, "write machine-readable JSON")
	f.BoolVar(jsonOutput, "j", false, "alias for --json")
	entry := f.String("entry", "", "file entry inside a ZIP")
	f.StringVar(entry, "e", "", "alias for --entry")
	f.Usage = func() {
		fmt.Fprintln(f.Output(), "usage: rompatcher hash [options] FILE\n\noptions:\n  -e, --entry NAME  file entry inside a ZIP\n  -j, --json        emit machine-readable JSON")
	}
	if err := parseInterspersed(f, args); err != nil {
		return err
	}
	if f.NArg() != 1 {
		return errors.New("hash requires FILE")
	}
	var result rompatcher.HashInfo
	if f.Arg(0) == "-" {
		b, _, err := readInput("-", *entry, rompatcher.InputAny, 0)
		if err != nil {
			return err
		}
		result = rompatcher.HashBytes(b)
	} else {
		path, _, cleanup, err := materializeInput(f.Arg(0), *entry, rompatcher.InputAny, 0)
		if err != nil {
			return err
		}
		defer cleanup()
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		result, err = rompatcher.HashReader(ctx, file)
		if err != nil {
			return err
		}
	}
	if *jsonOutput {
		return emit(true, result, "")
	}
	fmt.Printf("CRC32  %s\nMD5    %s\nSHA1   %s\n", result.CRC32, result.MD5, result.SHA1)
	return nil
}

func readInput(path, entry string, kind rompatcher.InputKind, maxSize uint64) ([]byte, string, error) {
	if path == "-" {
		reader := io.Reader(os.Stdin)
		if maxSize != 0 && maxSize < uint64(^uint64(0)>>1) {
			reader = io.LimitReader(reader, int64(maxSize)+1)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, "", err
		}
		if maxSize != 0 && uint64(len(data)) > maxSize {
			return nil, "", fmt.Errorf("input exceeds size limit: %d > %d", len(data), maxSize)
		}
		if bytes.HasPrefix(data, []byte{'P', 'K', 3, 4}) {
			return rompatcher.ReadZIPBytes(data, entry, kind, maxSize)
		}
		if entry != "" {
			return nil, "", errors.New("entry requires ZIP input")
		}
		return data, "stdin", nil
	}
	if isZIP(path) {
		return rompatcher.ReadZIP(path, entry, kind, maxSize)
	}
	if entry != "" {
		return nil, "", errors.New("entry requires ZIP input")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	if maxSize != 0 {
		info, err := file.Stat()
		if err != nil {
			return nil, "", err
		}
		if info.Size() < 0 || uint64(info.Size()) > maxSize {
			return nil, "", fmt.Errorf("input exceeds size limit: %d > %d", info.Size(), maxSize)
		}
	}
	b, err := io.ReadAll(file)
	return b, path, err
}

func materializeInput(path, entry string, kind rompatcher.InputKind, maxSize uint64) (string, string, func(), error) {
	if !isZIP(path) {
		if entry != "" {
			return "", "", func() {}, errors.New("entry requires ZIP input")
		}
		if maxSize != 0 {
			info, err := os.Stat(path)
			if err != nil {
				return "", "", func() {}, err
			}
			if info.Size() < 0 || uint64(info.Size()) > maxSize {
				return "", "", func() {}, fmt.Errorf("input exceeds size limit: %d > %d", info.Size(), maxSize)
			}
		}
		return path, path, func() {}, nil
	}
	tmp, err := os.CreateTemp("", "rompatcher-input-*")
	if err != nil {
		return "", "", func() {}, err
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}
	name, err := rompatcher.ExtractZIP(path, entry, kind, maxSize, tmp)
	if err != nil {
		cleanup()
		return "", "", func() {}, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", "", func() {}, err
	}
	return tmp.Name(), name, cleanup, nil
}

func writeOutput(path string, data []byte) error {
	if path == "-" {
		_, err := io.Copy(os.Stdout, bytes.NewReader(data))
		return err
	}
	return rompatcher.WriteFileAtomic(path, data)
}

func isZIP(path string) bool { return strings.EqualFold(filepath.Ext(path), ".zip") }

func emit(asJSON bool, value any, text string) error { return emitTo(asJSON, os.Stdout, value, text) }
func emitTo(asJSON bool, w io.Writer, value any, text string) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	}
	if text != "" {
		fmt.Fprintln(w, text)
	}
	return nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func assignPatchEntries(paths []string, entries []string) ([]string, error) {
	assigned := make([]string, len(paths))
	next := 0
	for index, path := range paths {
		if next < len(entries) && (path == "-" || isZIP(path)) {
			assigned[index] = entries[next]
			next++
		}
	}
	if next != len(entries) {
		return nil, errors.New("more --patch-entry values than ZIP or stdin patches")
	}
	return assigned, nil
}

func defaultOutputPath(sourcePath, sourceName string) string {
	if !isZIP(sourcePath) {
		return rompatcher.DefaultPatchedPath(sourcePath)
	}
	return rompatcher.DefaultPatchedPath(filepath.Base(sourceName))
}

// parseInterspersed keeps the standard flag package while allowing options
// before or after filenames, as users expect from a modern CLI.
func parseInterspersed(f *flag.FlagSet, args []string) error {
	flags, positional := make([]string, 0, len(args)), make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			continue
		}
		known := f.Lookup(name)
		if known == nil {
			continue
		}
		if boolean, ok := known.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue
		}
		if i+1 >= len(args) {
			return fmt.Errorf("flag needs an argument: %s", arg)
		}
		i++
		flags = append(flags, args[i])
	}
	output := f.Output()
	f.SetOutput(io.Discard)
	err := f.Parse(append(flags, positional...))
	f.SetOutput(output)
	if errors.Is(err, flag.ErrHelp) {
		f.Usage()
	}
	return err
}
