package jsengine

import (
	"bytes"
	"encoding/json"
	"sync"
)

// frame is one newline-delimited JSON message the tool JS writes to stdout. The "t"
// (type) field selects the variant: a host-call request, a log line, or the final
// result/error of the tool's run().
type frame struct {
	T     string          `json:"t"`
	ID    int             `json:"id"`
	Op    string          `json:"op"`
	Args  json.RawMessage `json:"args"`
	Level string          `json:"level"`
	Msg   string          `json:"msg"`
	Value json.RawMessage `json:"value"`
	Error string          `json:"error"`
}

// frameWriter is the JS→Go channel (the tool's stdout): it accumulates bytes and parses
// complete newline-delimited JSON frames, which the driver drains after each loop step.
type frameWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	frames []frame
}

func (w *frameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadBytes('\n')
		if err != nil { // no full line yet; put the partial back
			w.buf.Reset()
			w.buf.Write(line)
			break
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var f frame
		if json.Unmarshal(line, &f) == nil {
			w.frames = append(w.frames, f)
		}
	}
	return len(p), nil
}

// take returns and clears the frames parsed so far.
func (w *frameWriter) take() []frame {
	w.mu.Lock()
	defer w.mu.Unlock()
	f := w.frames
	w.frames = nil
	return f
}
