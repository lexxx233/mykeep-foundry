// Package store is Foundry's encrypted-at-rest backend: the "infrastructure tools run
// on". The live DB is an in-RAM SQLite database (modernc, pure Go); at open the whole DB
// is decrypted from foundry.db.enc and Deserialize'd into RAM, writes hit RAM, and a
// debounced flush re-seals the whole blob under the DEK. No plaintext DB touches the stick.
//
// It exposes the per-tool, namespaced + quota'd primitives the host functions broker:
// key-value, queue, cache (TTL), and blob storage, plus the marketplace tables (tools,
// grants, audit) used from M5 on.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"mykeep.ai/foundry/internal/secret"
)

// serializer is implemented by modernc's *conn (exported methods on an unexported type),
// reached via sql.Conn.Raw.
type serializer interface {
	Serialize() ([]byte, error)
	Deserialize(buf []byte) error
}

// ErrQuota is returned when a write would exceed a namespace's byte quota.
var ErrQuota = errors.New("storage quota exceeded")

const flushDebounce = 250 * time.Millisecond

// Store is the encrypted infra store. Safe for concurrent use.
type Store struct {
	blobPath string
	dek      []byte
	lock     *fileLock

	ctx  context.Context
	db   *sql.DB
	conn *sql.Conn

	mu           sync.Mutex
	dirty        bool
	closed       bool
	writeGen     uint64
	timer        *time.Timer
	lastFlushErr error

	flushMu      sync.Mutex
	persistedGen uint64
	failedGen    uint64
}

// Open opens (or creates) the encrypted store at blobPath, decrypting under dek. It takes
// an exclusive single-writer lock on the drive.
func Open(ctx context.Context, blobPath string, dek []byte) (*Store, error) {
	if len(dek) != secret.DEKLen {
		return nil, errors.New("dek must be 32 bytes")
	}
	lock, err := acquireLock(blobPath + ".lock")
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		lock.release()
		return nil, err
	}
	db.SetMaxOpenConns(1) // a single in-RAM connection holds the whole DB
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		lock.release()
		return nil, err
	}
	s := &Store{blobPath: blobPath, dek: append([]byte(nil), dek...), lock: lock, ctx: ctx, db: db, conn: conn}

	if blob, err := os.ReadFile(blobPath); err == nil {
		plain, err := secret.Open(dek, blob)
		if err != nil {
			_ = s.hardClose()
			return nil, err
		}
		if err := s.deserialize(plain); err != nil {
			_ = s.hardClose()
			return nil, fmt.Errorf("deserialize: %w", err)
		}
	} else if !os.IsNotExist(err) {
		_ = s.hardClose()
		return nil, err
	}
	if err := s.migrate(); err != nil {
		_ = s.hardClose()
		return nil, err
	}
	return s, nil
}

var schema = []string{
	`CREATE TABLE IF NOT EXISTS kv    (ns TEXT, k TEXT, v BLOB, bytes INTEGER, updated_at INTEGER, PRIMARY KEY(ns,k))`,
	`CREATE TABLE IF NOT EXISTS queue (ns TEXT, name TEXT, id INTEGER PRIMARY KEY AUTOINCREMENT, msg BLOB, bytes INTEGER, enq_at INTEGER)`,
	`CREATE TABLE IF NOT EXISTS cache (ns TEXT, k TEXT, v BLOB, bytes INTEGER, expires_at INTEGER, PRIMARY KEY(ns,k))`,
	`CREATE TABLE IF NOT EXISTS blob  (ns TEXT, name TEXT, data BLOB, bytes INTEGER, updated_at INTEGER, PRIMARY KEY(ns,name))`,
	`CREATE TABLE IF NOT EXISTS quota (ns TEXT PRIMARY KEY, limit_bytes INTEGER)`,
	`CREATE TABLE IF NOT EXISTS tools (name TEXT PRIMARY KEY, version TEXT, class TEXT, manifest BLOB, source BLOB, source_sha TEXT, installed_at INTEGER)`,
	`CREATE TABLE IF NOT EXISTS grants(tool TEXT PRIMARY KEY, caps BLOB, manifest_sha TEXT, granted_at INTEGER)`,
	`CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, tool TEXT, event TEXT, detail TEXT, prev_hash TEXT, hash TEXT)`,
}

func (s *Store) migrate() error {
	for _, stmt := range schema {
		if _, err := s.conn.ExecContext(s.ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// --- KV ---------------------------------------------------------------------

func (s *Store) KVSet(ns, key string, val []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkQuota(ns, "kv", key, len(val)); err != nil {
		return err
	}
	_, err := s.conn.ExecContext(s.ctx,
		`INSERT INTO kv(ns,k,v,bytes,updated_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(ns,k) DO UPDATE SET v=excluded.v, bytes=excluded.bytes, updated_at=excluded.updated_at`,
		ns, key, val, len(val), now())
	if err == nil {
		s.markDirtyLocked()
	}
	return err
}

func (s *Store) KVGet(ns, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v []byte
	err := s.conn.QueryRowContext(s.ctx, `SELECT v FROM kv WHERE ns=? AND k=?`, ns, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return v, err == nil, err
}

func (s *Store) KVDel(ns, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.ExecContext(s.ctx, `DELETE FROM kv WHERE ns=? AND k=?`, ns, key)
	if err == nil {
		s.markDirtyLocked()
	}
	return err
}

// --- Queue (FIFO) -----------------------------------------------------------

func (s *Store) QueuePush(ns, name string, msg []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkQuota(ns, "", "", len(msg)); err != nil {
		return err
	}
	_, err := s.conn.ExecContext(s.ctx,
		`INSERT INTO queue(ns,name,msg,bytes,enq_at) VALUES(?,?,?,?,?)`, ns, name, msg, len(msg), now())
	if err == nil {
		s.markDirtyLocked()
	}
	return err
}

// QueuePop removes and returns the oldest message on the named queue.
func (s *Store) QueuePop(ns, name string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id int64
	var msg []byte
	err := s.conn.QueryRowContext(s.ctx,
		`DELETE FROM queue WHERE id=(SELECT id FROM queue WHERE ns=? AND name=? ORDER BY id LIMIT 1) RETURNING id,msg`,
		ns, name).Scan(&id, &msg)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err == nil {
		s.markDirtyLocked()
	}
	return msg, err == nil, err
}

// --- Cache (TTL) ------------------------------------------------------------

func (s *Store) CacheSet(ns, key string, val []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkQuota(ns, "cache", key, len(val)); err != nil {
		return err
	}
	exp := int64(0)
	if ttl > 0 {
		exp = time.Now().Add(ttl).UnixMilli()
	}
	_, err := s.conn.ExecContext(s.ctx,
		`INSERT INTO cache(ns,k,v,bytes,expires_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(ns,k) DO UPDATE SET v=excluded.v, bytes=excluded.bytes, expires_at=excluded.expires_at`,
		ns, key, val, len(val), exp)
	if err == nil {
		s.markDirtyLocked()
	}
	return err
}

// CacheGet returns the value if present and unexpired; an expired entry is swept on read.
func (s *Store) CacheGet(ns, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v []byte
	var exp int64
	err := s.conn.QueryRowContext(s.ctx, `SELECT v,expires_at FROM cache WHERE ns=? AND k=?`, ns, key).Scan(&v, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if exp > 0 && time.Now().UnixMilli() >= exp {
		_, _ = s.conn.ExecContext(s.ctx, `DELETE FROM cache WHERE ns=? AND k=?`, ns, key)
		s.markDirtyLocked()
		return nil, false, nil
	}
	return v, true, nil
}

// --- Blob -------------------------------------------------------------------

func (s *Store) BlobPut(ns, name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkQuota(ns, "blob", name, len(data)); err != nil {
		return err
	}
	_, err := s.conn.ExecContext(s.ctx,
		`INSERT INTO blob(ns,name,data,bytes,updated_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(ns,name) DO UPDATE SET data=excluded.data, bytes=excluded.bytes, updated_at=excluded.updated_at`,
		ns, name, data, len(data), now())
	if err == nil {
		s.markDirtyLocked()
	}
	return err
}

func (s *Store) BlobGet(ns, name string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var data []byte
	err := s.conn.QueryRowContext(s.ctx, `SELECT data FROM blob WHERE ns=? AND name=?`, ns, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return data, err == nil, err
}

// --- Quota ------------------------------------------------------------------

// SetQuota sets a namespace's byte ceiling (0 removes the limit).
func (s *Store) SetQuota(ns string, limitBytes int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.ExecContext(s.ctx,
		`INSERT INTO quota(ns,limit_bytes) VALUES(?,?) ON CONFLICT(ns) DO UPDATE SET limit_bytes=excluded.limit_bytes`,
		ns, limitBytes)
	if err == nil {
		s.markDirtyLocked()
	}
	return err
}

// checkQuota rejects a write that would push the namespace past its limit. Must hold s.mu.
// table+key identify an entry being overwritten so its current bytes don't double-count.
func (s *Store) checkQuota(ns, table, key string, addBytes int) error {
	var limit int64
	err := s.conn.QueryRowContext(s.ctx, `SELECT limit_bytes FROM quota WHERE ns=?`, ns).Scan(&limit)
	if errors.Is(err, sql.ErrNoRows) || limit <= 0 {
		return nil // no limit set
	}
	if err != nil {
		return err
	}
	used, err := s.nsUsedLocked(ns)
	if err != nil {
		return err
	}
	var existing int64
	switch table {
	case "kv":
		_ = s.conn.QueryRowContext(s.ctx, `SELECT bytes FROM kv WHERE ns=? AND k=?`, ns, key).Scan(&existing)
	case "cache":
		_ = s.conn.QueryRowContext(s.ctx, `SELECT bytes FROM cache WHERE ns=? AND k=?`, ns, key).Scan(&existing)
	case "blob":
		_ = s.conn.QueryRowContext(s.ctx, `SELECT bytes FROM blob WHERE ns=? AND name=?`, ns, key).Scan(&existing)
	}
	if used-existing+int64(addBytes) > limit {
		return ErrQuota
	}
	return nil
}

func (s *Store) nsUsedLocked(ns string) (int64, error) {
	var total int64
	for _, q := range []string{
		`SELECT COALESCE(SUM(bytes),0) FROM kv WHERE ns=?`,
		`SELECT COALESCE(SUM(bytes),0) FROM queue WHERE ns=?`,
		`SELECT COALESCE(SUM(bytes),0) FROM cache WHERE ns=?`,
		`SELECT COALESCE(SUM(bytes),0) FROM blob WHERE ns=?`,
	} {
		var n int64
		if err := s.conn.QueryRowContext(s.ctx, q, ns).Scan(&n); err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// --- persistence ------------------------------------------------------------

func now() int64 { return time.Now().UnixMilli() }

// markDirtyLocked flags a write and (re)arms the debounce timer. Must hold s.mu.
func (s *Store) markDirtyLocked() {
	s.dirty = true
	s.writeGen++
	if s.closed {
		return
	}
	if s.timer == nil {
		s.timer = time.AfterFunc(flushDebounce, func() { _ = s.reseal() })
	} else {
		s.timer.Reset(flushDebounce)
	}
}

// Flush forces a synchronous re-seal of the current DB to disk.
func (s *Store) Flush() error { return s.reseal() }

// FlushErr reports the last persistence error (surfaced via health), or nil.
func (s *Store) FlushErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastFlushErr
}

// reseal snapshots the in-RAM DB under s.mu (a fast copy), then encrypts + writes the
// snapshot WITHOUT holding s.mu, so a slow USB write never blocks tool storage calls. A
// monotonic generation guard ensures a stale snapshot can't overwrite a newer blob.
func (s *Store) reseal() error {
	s.mu.Lock()
	if !s.dirty || s.closed {
		s.mu.Unlock()
		return nil
	}
	raw, err := s.serializeLocked()
	if err != nil {
		s.lastFlushErr = err
		s.mu.Unlock()
		return err
	}
	gen := s.writeGen
	s.dirty = false
	s.mu.Unlock()

	s.flushMu.Lock()
	if gen <= s.persistedGen {
		s.flushMu.Unlock()
		return nil
	}
	sealed, werr := secret.Seal(s.dek, raw)
	if werr == nil {
		werr = atomicWrite(s.blobPath, sealed)
	}
	if werr == nil {
		s.persistedGen = gen
	}
	s.flushMu.Unlock()

	s.mu.Lock()
	if werr != nil {
		s.lastFlushErr = werr
		s.dirty = true
		if gen > s.failedGen {
			s.failedGen = gen
		}
	} else if gen >= s.failedGen {
		s.lastFlushErr = nil
	}
	s.mu.Unlock()
	return werr
}

func (s *Store) serializeLocked() ([]byte, error) {
	var out []byte
	err := s.conn.Raw(func(dc any) error {
		ser, ok := dc.(serializer)
		if !ok {
			return errors.New("driver does not support Serialize")
		}
		b, serr := ser.Serialize()
		out = b
		return serr
	})
	return out, err
}

func (s *Store) deserialize(plain []byte) error {
	return s.conn.Raw(func(dc any) error {
		ser, ok := dc.(serializer)
		if !ok {
			return errors.New("driver does not support Deserialize")
		}
		return ser.Deserialize(plain)
	})
}

// Close flushes, releases the connection, and drops the drive lock.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	s.mu.Unlock()

	ferr := s.reseal() // flush while still open (reseal bails once closed)

	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	herr := s.hardClose()
	if ferr != nil {
		return ferr
	}
	return herr
}

func (s *Store) hardClose() error {
	if s.conn != nil {
		_ = s.conn.Close()
	}
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	if s.lock != nil {
		s.lock.release()
	}
	for i := range s.dek {
		s.dek[i] = 0
	}
	return err
}
