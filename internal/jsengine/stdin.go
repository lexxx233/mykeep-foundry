package jsengine

import (
	"io"
	"sync"
	"time"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
)

// respPipe is the Go→JS response channel: host-call responses the Go driver writes here
// are delivered to the tool's stdin, where a read handler resolves the matching Promise.
// It is a pollable stdin so the reactor's PollIO can fire the JS read handler.
//
// Adapted from the reactor's reference PollableStdinBuffer (which is test-only).
type respPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	offset int
	closed bool
}

func newRespPipe() *respPipe {
	p := &respPipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *respPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	p.buf = append(p.buf, b...)
	p.cond.Broadcast()
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
	p.cond.Broadcast()
	return nil
}

// Poll reports whether data is ready, matching the signature wazero detects for pollable stdin.
func (p *respPipe) Poll(flag experimentalsys.Pflag, timeoutMillis int32) (bool, experimentalsys.Errno) {
	if flag != experimentalsys.POLLIN {
		return false, experimentalsys.ENOTSUP
	}
	p.mu.Lock()
	if len(p.buf) > p.offset || p.closed {
		p.mu.Unlock()
		return true, 0
	}
	if timeoutMillis == 0 {
		p.mu.Unlock()
		return false, 0
	}
	done := make(chan struct{})
	go func() {
		p.mu.Lock()
		for len(p.buf) <= p.offset && !p.closed {
			p.cond.Wait()
		}
		p.mu.Unlock()
		close(done)
	}()
	p.mu.Unlock()
	if timeoutMillis < 0 {
		<-done
	} else {
		select {
		case <-done:
		case <-time.After(time.Duration(timeoutMillis) * time.Millisecond):
			return false, 0
		}
	}
	p.mu.Lock()
	ready := len(p.buf) > p.offset || p.closed
	p.mu.Unlock()
	return ready, 0
}

var _ experimentalsys.Pollable = (*respPipe)(nil)
