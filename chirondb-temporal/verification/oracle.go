// Test driver. Donor codec, index reader and writer declarations are assembled
// verbatim by verify.py into the same temporary Go package.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

type row struct {
	t    int64
	tag  byte
	bits uint64
}

func (r row) UnixNano() int64 { return r.t }

type Values []row

func (v Values) Encode(buf []byte) ([]byte, error) {
	te := NewTimeEncoder(len(v))
	fe := NewFloatEncoder()
	be := NewBooleanEncoder(len(v))
	for _, p := range v {
		te.Write(p.t)
		if p.tag == 0 {
			fe.Write(math.Float64frombits(p.bits))
		} else {
			be.Write(p.bits == 1)
		}
	}
	ts, err := te.Bytes()
	if err != nil {
		return nil, err
	}
	var vals []byte
	if v[0].tag == 0 {
		fe.Flush()
		vals, err = fe.Bytes()
	} else {
		vals, err = be.Bytes()
	}
	if err != nil {
		return nil, err
	}
	return packBlock(buf, v[0].tag, ts, vals), nil
}
func readInput(path string) map[string]Values {
	f, err := os.Open(path)
	check(err)
	defer f.Close()
	m := map[string]Values{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 6 {
			panic("invalid fixture row")
		}
		var key bytes.Buffer
		for _, p := range fields[:3] {
			check(binary.Write(&key, binary.BigEndian, uint16(len(p))))
			key.WriteString(p)
		}
		t, err := strconv.ParseInt(fields[3], 10, 64)
		check(err)
		kind, err := strconv.ParseUint(fields[4], 10, 8)
		check(err)
		bits, err := strconv.ParseUint(fields[5], 16, 64)
		check(err)
		m[key.String()] = append(m[key.String()], row{t, byte(kind), bits})
	}
	check(scanner.Err())
	for _, rows := range m {
		sort.Slice(rows, func(i, j int) bool { return rows[i].t < rows[j].t })
	}
	return m
}
func check(err error) {
	if err != nil {
		panic(err)
	}
}
func writeFile(path string, m map[string]Values) {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f, err := os.Create(path)
	check(err)
	w, err := NewTSMWriter(f)
	check(err)
	for _, k := range keys {
		rows := m[k]
		for len(rows) > 0 {
			n := min(1000, len(rows))
			check(w.Write([]byte(k), rows[:n]))
			rows = rows[n:]
		}
	}
	check(w.WriteIndex())
	check(w.Close())
}

// Run upstream timestamp and typed value decoders on each indexed payload.
func readFile(data []byte) map[string]Values {
	check(verifyVersion(bytes.NewReader(data)))
	pos := binary.BigEndian.Uint64(data[len(data)-8:])
	index := data[pos : len(data)-8]
	m := map[string]Values{}
	for len(index) > 0 {
		n, k := readKey(index)
		var e indexEntries
		used, err := readEntries(index[n:], &e)
		check(err)
		index = index[n+used:]
		for _, block := range e.entries {
			b := data[block.Offset : block.Offset+int64(block.Size)]
			if crc32.ChecksumIEEE(b[4:]) != binary.BigEndian.Uint32(b[:4]) || b[4] != e.Type {
				panic("bad block")
			}
			ts, vs, err := unpackBlock(b[5:])
			check(err)
			var td TimeDecoder
			td.Init(ts)
			var fd FloatDecoder
			var bd BooleanDecoder
			if e.Type == 0 {
				check(fd.SetBytes(vs))
			} else {
				bd.SetBytes(vs)
			}
			for td.Next() {
				var bits uint64
				if e.Type == 0 {
					if !fd.Next() {
						panic("short float")
					}
					bits = math.Float64bits(fd.Values())
				} else {
					if !bd.Next() {
						panic("short bool")
					}
					if bd.Read() {
						bits = 1
					}
				}
				m[string(k)] = append(m[string(k)], row{td.Read(), e.Type, bits})
			}
			check(td.Error())
			if e.Type == 0 {
				if fd.Next() {
					panic("extra float")
				}
				check(fd.Error())
			} else {
				if bd.Next() {
					panic("extra boolean")
				}
				check(bd.Error())
			}
		}
	}
	return m
}
func main() {
	args := os.Args[1:]
	m := readInput(args[1])
	if args[0] == "write" {
		writeFile(args[2], m)
		return
	}
	b, err := os.ReadFile(args[2])
	check(err)
	if args[0] == "keylen" {
		pos := binary.BigEndian.Uint64(b[len(b)-8:])
		b[pos+1] ^= 64
		altered := readFile(b)
		if len(m) != 2 || len(altered) != 1 {
			panic("did not reproduce key loss")
		}
		for k := range m {
			if _, ok := altered[k]; ok {
				panic("expected displaced key")
			}
		}
		fmt.Println("unchecked reference index: keylen flip silently maps two series to one wrong key")
		return
	}
	got := readFile(b)
	if len(m) != len(got) {
		panic("series mismatch")
	}
	for k, rows := range m {
		if len(rows) != len(got[k]) {
			panic("row count")
		}
		for i, r := range rows {
			if r != got[k][i] {
				panic(fmt.Sprintf("value mismatch %q %d", k, i))
			}
		}
	}
}
