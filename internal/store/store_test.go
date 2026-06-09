package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
)

func testDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	return dek
}

func open(t *testing.T, path string, dek []byte) *Store {
	t.Helper()
	s, err := Open(context.Background(), path, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// TestKVPersistsAcrossReopen proves writes are sealed and survive a close/reopen — the
// core "encrypted backend on the stick" guarantee.
func TestKVPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foundry.db.enc")
	dek := testDEK(t)

	s := open(t, path, dek)
	if err := s.KVSet("toolA", "greeting", []byte("hello")); err != nil {
		t.Fatalf("KVSet: %v", err)
	}
	if err := s.QueuePush("toolA", "jobs", []byte("job-1")); err != nil {
		t.Fatalf("QueuePush: %v", err)
	}
	if err := s.BlobPut("toolA", "data.bin", []byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("BlobPut: %v", err)
	}
	if err := s.Close(); err != nil { // Close flushes
		t.Fatalf("Close: %v", err)
	}

	s2 := open(t, path, dek)
	defer s2.Close()
	if v, ok, _ := s2.KVGet("toolA", "greeting"); !ok || string(v) != "hello" {
		t.Fatalf("KVGet after reopen => %q ok=%v", v, ok)
	}
	if v, ok, _ := s2.QueuePop("toolA", "jobs"); !ok || string(v) != "job-1" {
		t.Fatalf("QueuePop after reopen => %q ok=%v", v, ok)
	}
	if v, ok, _ := s2.BlobGet("toolA", "data.bin"); !ok || !bytes.Equal(v, []byte{1, 2, 3, 4}) {
		t.Fatalf("BlobGet after reopen => %v ok=%v", v, ok)
	}
}

// TestWrongDEKFails proves a wrong key cannot open the sealed store.
func TestWrongDEKFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foundry.db.enc")
	dek := testDEK(t)
	s := open(t, path, dek)
	_ = s.KVSet("ns", "k", []byte("v"))
	s.Close()

	if _, err := Open(context.Background(), path, testDEK(t)); err == nil {
		t.Fatal("opened sealed store with the wrong DEK")
	}
}

// TestNamespaceIsolation proves one tool cannot read another's keys.
func TestNamespaceIsolation(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "f.db.enc"), testDEK(t))
	defer s.Close()
	_ = s.KVSet("toolA", "secret", []byte("A-only"))
	if _, ok, _ := s.KVGet("toolB", "secret"); ok {
		t.Fatal("toolB read toolA's namespace")
	}
}

// TestCacheTTL proves an expired cache entry is swept on read.
func TestCacheTTL(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "f.db.enc"), testDEK(t))
	defer s.Close()
	_ = s.CacheSet("ns", "k", []byte("v"), 40*time.Millisecond)
	if _, ok, _ := s.CacheGet("ns", "k"); !ok {
		t.Fatal("cache entry missing before expiry")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok, _ := s.CacheGet("ns", "k"); ok {
		t.Fatal("expired cache entry was returned")
	}
}

// TestQuota proves a namespace byte ceiling is enforced and counts overwrites correctly.
func TestQuota(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "f.db.enc"), testDEK(t))
	defer s.Close()
	if err := s.SetQuota("ns", 100); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	if err := s.KVSet("ns", "a", bytes.Repeat([]byte("x"), 60)); err != nil {
		t.Fatalf("first write under quota failed: %v", err)
	}
	if err := s.KVSet("ns", "b", bytes.Repeat([]byte("y"), 60)); err != ErrQuota {
		t.Fatalf("over-quota write => %v, want ErrQuota", err)
	}
	// overwriting an existing key with a smaller value must not double-count
	if err := s.KVSet("ns", "a", bytes.Repeat([]byte("x"), 10)); err != nil {
		t.Fatalf("overwrite within quota failed: %v", err)
	}
	if err := s.KVSet("ns", "b", bytes.Repeat([]byte("y"), 60)); err != nil {
		t.Fatalf("write after freeing space failed: %v", err)
	}
}

// TestSingleInstanceLock proves a second opener on the same drive is refused.
func TestSingleInstanceLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.db.enc")
	dek := testDEK(t)
	s := open(t, path, dek)
	defer s.Close()
	if _, err := Open(context.Background(), path, dek); err != ErrAlreadyRunning {
		t.Fatalf("second open => %v, want ErrAlreadyRunning", err)
	}
}
