package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"io"
	"log"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const (
	CISO_MAGIC       = 0x4F534943 // CISO
	CISO_HEADER_SIZE = 0x18       // 24
	CISO_BLOCK_SIZE  = 0x800      // 2048
)

type CisoHeader struct {
	Magic            uint32
	HeaderSize       uint32
	UncompressedSize uint64
	BlockSize        uint32
	Ver              uint8
	Align            uint8
	PaddingBytes     uint16
}

func (hdr *CisoHeader) Validate() error {
	if hdr.Magic != CISO_MAGIC {
		return errors.New("validate: input seems not to be a CSO file")
	}
	if hdr.HeaderSize != CISO_HEADER_SIZE {
		// according to document, this field has not to be accurate and
		// under no circumstances header size differs from 0x18
		fmt.Fprintln(os.Stderr, "warning: validate: CISO header size differs from 0x18")
		hdr.HeaderSize = CISO_HEADER_SIZE
	}
	if hdr.Ver >= 2 {
		return errors.New("validate: CSO version too high")
	}
	if hdr.Align != 0 {
		return errors.New("validate: CSO with align offset decompression not implemented")
	}
	return nil
}

func (hdr *CisoHeader) WriteTo(w io.Writer) (n int64, err error) {
	err = binary.Write(w, binary.LittleEndian, hdr)
	n = int64(CISO_HEADER_SIZE)
	return
}

func (hdr *CisoHeader) BlockCount() int {
	count := int(hdr.UncompressedSize) / int(hdr.BlockSize)
	if remainder := int(hdr.UncompressedSize) % int(hdr.BlockSize); remainder == 0 {
		return count
	} else {
		fmt.Fprintf(os.Stderr, "warning: cannot divide iso file by block size evenly, %d bytes remained\n", remainder)
		return count + 1
	}
}

var myBar pb.ProgressBarTemplate = `{{with string . "prefix"}}{{.}} {{end}}{{counters . }} {{bar . }} {{percent . }} {{speed . "%s blocks/s"}}{{with string . "suffix"}} {{.}}{{end}}`

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := unit, 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func writeCsoIndexTable(w io.Writer, entries []uint32) {
	err := binary.Write(w, binary.LittleEndian, entries)
	if err != nil {
		panic(err)
	}
}

type indexedBlock struct {
	index      int
	data       []byte
	compressed bool
}

func CompressIso(out io.WriteSeeker, in io.Reader, fileSize int64, compressionLevel int) {
	hdr := CisoHeader{
		CISO_MAGIC,
		CISO_HEADER_SIZE,
		uint64(fileSize),
		CISO_BLOCK_SIZE,
		1, 0, 0,
	}

	if _, err := hdr.WriteTo(out); err != nil {
		panic(err)
	}

	blockCount := hdr.BlockCount()

	bar := myBar.New(blockCount).Start()

	numCPU := runtime.NumCPU()

	rawChan := make(chan indexedBlock)
	cookedChan := make(chan indexedBlock)

	var wg sync.WaitGroup
	wg.Add(blockCount)

	go func() {
		wg.Wait()
		close(rawChan)
		close(cookedChan)
	}()

	go func() { // reader
		for i := 0; i < blockCount; i++ {
			rawData := make([]byte, CISO_BLOCK_SIZE)

			if _, ioErr := in.Read(rawData); ioErr != nil {
				panic(ioErr)
			}
			ib := indexedBlock{
				index:      i,
				data:       rawData,
				compressed: false,
			}
			rawChan <- ib
		}
	}()

	for i := 0; i < numCPU; i++ {
		go func() { // compressor
			var buf bytes.Buffer
			compressor, _ := flate.NewWriter(nil, compressionLevel)

			for block := range rawChan {
				buf.Reset()
				compressor.Reset(&buf)

				rawDataSize := len(block.data)
				if _, err := compressor.Write(block.data); err != nil {
					panic(err)
				}
				_ = compressor.Close()

				if buf.Len() < rawDataSize {
					block.data = buf.Bytes()
					block.compressed = true
				}
				cookedChan <- block
			}
		}()
	}

	// prepare index table
	indexTable := make([]uint32, blockCount+1)
	writeCsoIndexTable(out, indexTable)

	offset64, _ := out.Seek(0, io.SeekCurrent)
	offset := uint32(offset64)

	blockTmp := make(map[int]indexedBlock)
	nextIndex := 0

	compressedBlockCount := 0

	for block := range cookedChan {
		blockTmp[block.index] = block

		for v, ok := blockTmp[nextIndex]; ok; v, ok = blockTmp[nextIndex] {
			delete(blockTmp, nextIndex)

			if v.compressed {
				indexTable[v.index] = offset
				compressedBlockCount++
			} else {
				indexTable[v.index] = offset | 0x80000000
			}

			l, ioErr := out.Write(v.data)
			if ioErr != nil {
				panic(ioErr)
			}

			offset += uint32(l)
			nextIndex++

			wg.Done()
			bar.Increment()
		}
	}

	indexTable[blockCount] = offset
	_, _ = out.Seek(CISO_HEADER_SIZE, io.SeekStart)
	writeCsoIndexTable(out, indexTable)

	bar.Finish()

	ratio := float64(offset) / float64(fileSize) * 100
	fmt.Printf("%s -> %s @ %.2f%%\n",
		formatBytes(fileSize), formatBytes(int64(offset)), ratio)
}

func DecompressCso(out io.Writer, in io.ReadSeeker) error {
	hdr := CisoHeader{}

	if err := binary.Read(in, binary.LittleEndian, &hdr); err != nil {
		return err
	}
	if err := hdr.Validate(); err != nil {
		return err
	}

	blockCount := hdr.BlockCount()
	indexTable := make([]uint32, blockCount+1)
	for i, _ := range indexTable {
		p := make([]byte, 4)
		_, err := in.Read(p)
		if err != nil {
			return err
		}
		indexTable[i] = binary.LittleEndian.Uint32(p)
	}

	bar := myBar.New(blockCount).Start()

	for i, v := range indexTable[:blockCount] {

		compressed := int32(v) >= 0
		pos := v & 0x7FFFFFFF
		length := (indexTable[i+1] & 0x7FFFFFFF) - pos

		buf := make([]byte, length)

		if _, err := in.Read(buf); err != nil {
			return err
		}

		var reader io.Reader = bytes.NewReader(buf)
		if compressed {
			reader = flate.NewReader(reader)
		}

		if _, err := io.Copy(out, reader); err != nil {
			return err
		}
		bar.Increment()
	}
	bar.Finish()

	offset, _ := in.Seek(0, io.SeekEnd)

	ratio := float64(offset) / float64(hdr.UncompressedSize) * 100
	fmt.Printf("%s -> %s @ %.2f%%\n",
		formatBytes(offset), formatBytes(int64(hdr.UncompressedSize)), ratio)

	return nil
}

func fallbackArgs(filename string) (compressionLevel int, outFile string) {
	ext := path.Ext(filename)
	switch strings.ToLower(ext) {
	case ".cso":
		return 0, strings.TrimSuffix(filename, ext) + ".iso"
	case ".iso":
		return 9, strings.TrimSuffix(filename, ext) + ".cso"
	default:
		fmt.Fprintln(os.Stderr,
			"bad arg: FILE must be .cso or .iso or provide compression level",
			"see --help for more details")
		os.Exit(1)
		return
	}
}

func main() {
	var compressionLevel int
	var file, outFile string

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr,
			"Usage: cisou [LEVEL] FILE [OUT_FILE]",
			"Compress or decompress FILE where FILE is a PSP disk image.",
			"",
			"  LEVEL:",
			"    0       = decompress",
			"    1-9     = compress level",
			"    omitted = depends on FILE extension name ",
			"              decompress .cso; compress .iso in level 9",
			"  OUT_FILE:",
			"    output file name",
			"    if omitted, fallback to FILE with the other extension name",
		)
	}
	flag.Parse()

	args := flag.Args()
	switch len(args) {
	case 1:
		file = args[0]
		compressionLevel, outFile = fallbackArgs(file)
	case 2:
		i, err := strconv.Atoi(args[0])
		if err == nil {
			compressionLevel = i
			file = args[1]
			_, outFile = fallbackArgs(file)
		} else {
			file = args[0]
			outFile = args[1]
			compressionLevel, _ = fallbackArgs(file)
		}
	case 3:
		i, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr,
				"bad arg: compression level must be 0-9", "see --help for more details")
			os.Exit(1)
		}
		compressionLevel = i
		file = args[1]
		outFile = args[2]
	case 0:
		flag.Usage()
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr,
			"bad arg: too many args", "see --help for more details")
		os.Exit(1)
	}

	fileInfo, err := os.Stat(file)
	if err != nil {
		log.Fatalln(err)
	}
	in, err := os.Open(file)
	if err != nil {
		log.Fatalln(err)
	}
	defer in.Close()
	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	if err != nil {
		log.Fatalln(err)
	}
	defer out.Close()

	if compressionLevel == 0 {
		if err := DecompressCso(out, in); err != nil {
			log.Fatalln(err)
		}
	} else if compressionLevel >= 1 && compressionLevel <= 9 {
		CompressIso(out, in, fileInfo.Size(), compressionLevel)
	} else {
		fmt.Fprintln(os.Stderr,
			"bad arg: compression level must be 0-9", "see --help for more details")
		os.Exit(1)
	}
}
