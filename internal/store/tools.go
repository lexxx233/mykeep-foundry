package store

import (
	"database/sql"
	"errors"
)

// ToolRow is a persisted tool: its manifest + JS source + provenance class.
type ToolRow struct {
	Name      string
	Version   string
	Class     string // "dev" | "marketplace"
	Manifest  []byte
	Source    []byte
	SourceSHA string
}

// PutTool inserts or replaces an installed tool.
func (s *Store) PutTool(t ToolRow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.ExecContext(s.ctx,
		`INSERT INTO tools(name,version,class,manifest,source,source_sha,installed_at) VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET version=excluded.version, class=excluded.class,
		   manifest=excluded.manifest, source=excluded.source, source_sha=excluded.source_sha,
		   installed_at=excluded.installed_at`,
		t.Name, t.Version, t.Class, t.Manifest, t.Source, t.SourceSHA, now())
	if err == nil {
		s.markDirtyLocked()
	}
	return err
}

// GetTool returns an installed tool by name.
func (s *Store) GetTool(name string) (*ToolRow, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var t ToolRow
	err := s.conn.QueryRowContext(s.ctx,
		`SELECT name,version,class,manifest,source,source_sha FROM tools WHERE name=?`, name).
		Scan(&t.Name, &t.Version, &t.Class, &t.Manifest, &t.Source, &t.SourceSHA)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &t, true, nil
}

// ListTools returns all installed tools (manifest + class; source omitted).
func (s *Store) ListTools() ([]ToolRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.conn.QueryContext(s.ctx, `SELECT name,version,class,manifest,source_sha FROM tools ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ToolRow
	for rows.Next() {
		var t ToolRow
		if err := rows.Scan(&t.Name, &t.Version, &t.Class, &t.Manifest, &t.SourceSHA); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTool removes a tool and its grant.
func (s *Store) DeleteTool(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.conn.ExecContext(s.ctx, `DELETE FROM tools WHERE name=?`, name); err != nil {
		return err
	}
	if _, err := s.conn.ExecContext(s.ctx, `DELETE FROM grants WHERE tool=?`, name); err != nil {
		return err
	}
	s.markDirtyLocked()
	return nil
}

// PutGrant stores the human-approved capability grant for a tool, bound to manifestSHA.
func (s *Store) PutGrant(tool string, caps []byte, manifestSHA string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.ExecContext(s.ctx,
		`INSERT INTO grants(tool,caps,manifest_sha,granted_at) VALUES(?,?,?,?)
		 ON CONFLICT(tool) DO UPDATE SET caps=excluded.caps, manifest_sha=excluded.manifest_sha, granted_at=excluded.granted_at`,
		tool, caps, manifestSHA, now())
	if err == nil {
		s.markDirtyLocked()
	}
	return err
}

// GetGrant returns a tool's stored grant (caps blob + the manifest hash it was bound to).
func (s *Store) GetGrant(tool string) (caps []byte, manifestSHA string, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.conn.QueryRowContext(s.ctx, `SELECT caps,manifest_sha FROM grants WHERE tool=?`, tool).Scan(&caps, &manifestSHA)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	return caps, manifestSHA, true, nil
}
