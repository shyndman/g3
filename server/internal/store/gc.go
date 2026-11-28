package store

// BackingRefs is every Drive file reference the database still holds. The
// garbage collector deletes only files absent from this set, so anything the
// metadata still points at — live objects included — is untouchable.
type BackingRefs struct {
	FileIDs   []string // single-file objects and staged multipart parts
	Manifests []string // parts manifests (raw JSON) of multipart objects
}

// AllBackingRefs collects those references across objects and staged uploads.
func (s *Store) AllBackingRefs() (BackingRefs, error) {
	var refs BackingRefs
	ids, err := s.scanStrings(`SELECT drive_file_id FROM objects WHERE drive_file_id IS NOT NULL`)
	if err != nil {
		return refs, err
	}
	refs.FileIDs = ids
	staged, err := s.scanStrings(`SELECT drive_file_id FROM multipart_parts`)
	if err != nil {
		return refs, err
	}
	refs.FileIDs = append(refs.FileIDs, staged...)
	refs.Manifests, err = s.scanStrings(`SELECT parts FROM objects WHERE parts IS NOT NULL`)
	return refs, err
}

// StaleMultipartIDs lists uploads initiated before `before` (RFC3339) — the
// ones a client started and never completed or aborted.
func (s *Store) StaleMultipartIDs(before string) ([]string, error) {
	return s.scanStrings(`SELECT upload_id FROM multipart_uploads WHERE created_at < ?`, before)
}

// ObjectCount is the total number of stored objects, used as a sanity check
// before the collector is allowed to delete anything.
func (s *Store) ObjectCount() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM objects`).Scan(&n)
	return n, err
}

func (s *Store) scanStrings(query string, args ...any) ([]string, error) {
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ManifestReadMode controls whether usage can be reported with unreadable manifests.
type ManifestReadMode bool

const (
	SkipUnreadableManifests   ManifestReadMode = false
	FailOnUnreadableManifests ManifestReadMode = true
)

// UsageByAccount sums G3's single-file objects, completed multipart objects,
// and staged parts in one SQLite snapshot. Completion writes the manifest
// before deleting the staged rows, so the manifest takes precedence by file ID.
func (s *Store) UsageByAccount(mode ManifestReadMode) (map[string]int64, error) {
	// a, f, and s are the account ID, Drive file ID, and size in s3.manifestPart.
	rows, err := s.DB.Query(`
		WITH completed_parts(account_id, drive_file_id, size) AS MATERIALIZED (
			SELECT part.value ->> '$.a', part.value ->> '$.f', part.value ->> '$.s'
			FROM objects CROSS JOIN json_each(
				CASE WHEN ? OR json_valid(objects.parts) THEN objects.parts END
			) AS part
			WHERE part.type = 'object'
		), backing_bytes(account_id, size) AS (
			SELECT account_id, size FROM objects WHERE account_id IS NOT NULL
			UNION ALL
			SELECT account_id, size FROM completed_parts WHERE account_id IS NOT NULL
			UNION ALL
			SELECT account_id, size FROM multipart_parts
			WHERE drive_file_id NOT IN (
				SELECT drive_file_id FROM completed_parts WHERE drive_file_id IS NOT NULL
			)
		)
		SELECT account_id, SUM(size) FROM backing_bytes GROUP BY account_id
	`, mode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	usage := make(map[string]int64)
	for rows.Next() {
		var id string
		var size int64
		if err := rows.Scan(&id, &size); err != nil {
			return nil, err
		}
		usage[id] = size
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return usage, nil
}
