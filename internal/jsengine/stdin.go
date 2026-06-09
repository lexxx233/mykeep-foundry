package jsengine

import (
	"io"
	"sync"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
)

// respPipe is the Go→JS response channel: host-call responses the Go driver writes here
// are delivered to the tool's stdin, where a read handler resolves the matching Promise.
// It is a pollable stdin so the reactor's PollIO can fire the JS read handler.
//
// The driver always writes a response BEFORE poking PollIO, so Poll never needs to block —
// it is a non-blocking readiness check, which keeps respPipe free of background goroutines.
type respPipe struct {
	mu     sync.Mutex
	buf    []byte
	offset int
	closed bool
}

func newRespPipe() *respPipe { return &respPipe{} }

func (p *respPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	p.buf = append(p.buf, b...)
	return len(b), nil
}

func (p *respPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if avail := len(p.buf) - p.offset; avail <= 0 {
		if p.closed {
			return 0, io.EOF
		}
		return 0, nil // non-blocking: wazero expects 0,nil when empty
	}
	n := copy(b, p.buf[p.offset:])
	p.offset += n
	if p.offset >= len(p.buf) {
		p.buf, p.offset = nil, 0
	}
	return n, nil
}

func (p *respPipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// Poll reports current readiness without blocking, matching the signature wazero detects
// for pollable stdin.
func (p *respPipe) Poll(flag experimentalsys.Pflag, _ int32) (bool, experimentalsys.Errno) {
	if flag != experimentalsys.POLLIN {
		return false, experimentalsys.ENOTSUP
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.buf) > p.offset || p.closed, 0
}

var _ experimentalsys.Pollable = (*respPipe)(nil)
