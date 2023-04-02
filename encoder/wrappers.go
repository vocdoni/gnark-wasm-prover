package encoder

import (
	"encoding/gob"
	"io"
)

type WriterCounter struct {
	W io.Writer
	N int64
}

func (w *WriterCounter) Write(p []byte) (n int, err error) {
	n, err = w.W.Write(p)
	w.N += int64(n)
	return
}

type ReaderCounter struct {
	R io.Reader
	N int64
}

func (cr *ReaderCounter) Read(p []byte) (int, error) {
	n, err := cr.R.Read(p)
	cr.N += int64(n)
	return n, err
}

func EncodeToGob(w io.Writer, v interface{}) (int64, error) {
	wc := &WriterCounter{W: w}
	enc := gob.NewEncoder(wc)
	err := enc.Encode(v)
	return wc.N, err
}

func DecodeFromGob(r io.Reader, v interface{}) (int64, error) {
	cr := &ReaderCounter{R: r}
	dec := gob.NewDecoder(cr)
	err := dec.Decode(v)
	return cr.N, err
}
