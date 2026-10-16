package aarvion

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const DPID = "sdk"

const provenanceSchema = `
CREATE TABLE IF NOT EXISTS decisions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    record_json TEXT NOT NULL,
    row_hash TEXT NOT NULL,
    pushed INTEGER NOT NULL DEFAULT 0
);
`

const (
	DefaultAutoflushInterval = 5 * time.Second
	flushTimeout             = 15 * time.Second
)

type RecordInput struct {
	Method      string
	Path        string
	Host        string
	Decision    any
	PolicyID    any
	PolicyIDs   []string
	Reason      any
	Redactions  any
	LatencyMs   any
	Enforced    *bool
	RequestBody any
	OnBehalfOf  any
	RiskTier    any
	CallSite    any
}

func rowHash(prevHash string, payload any) (string, error) {
	serialized, err := pyDumps(payload, jsonSorted)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte("|"))
	h.Write([]byte(serialized))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func replicaID(runtimeKey string) string {
	rest := strings.TrimPrefix(runtimeKey, "aav_dev_")
	id, _, _ := strings.Cut(rest, ".")
	if id == "" {
		return "sdk"
	}
	return id
}

func isoNow() string {
	return isoformat(time.Now().UTC())
}

func isoformat(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s + "+00:00"
}

type Recorder struct {
	cfg      *Config
	tenant   string
	replica  string
	mu       sync.Mutex
	db       *sql.DB
	prevHash string
	closed   atomic.Bool
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func NewRecorder(cfg *Config, dbPath, tenant string, autoflushInterval time.Duration) (*Recorder, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(provenanceSchema); err != nil {
		db.Close()
		return nil, err
	}
	prev := "0"
	var rh string
	switch err := db.QueryRow("SELECT row_hash FROM decisions ORDER BY seq DESC LIMIT 1").Scan(&rh); err {
	case nil:
		prev = rh
	case sql.ErrNoRows:
	default:
		db.Close()
		return nil, err
	}
	r := &Recorder{cfg: cfg, tenant: tenant, replica: replicaID(cfg.RuntimeKey), db: db, prevHash: prev,
		stop: make(chan struct{})}
	if autoflushInterval > 0 {
		r.done = make(chan struct{})
		go r.autoflush(autoflushInterval)
	}
	return r, nil
}

func (r *Recorder) autoflush(interval time.Duration) {
	defer close(r.done)
	client := newPyHTTPClient(flushTimeout, false)
	defer client.CloseIdleConnections()
	t := time.NewTimer(interval)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			func() {
				defer func() { _ = recover() }()
				_, _ = r.flush(client)
			}()
			t.Reset(interval)
		}
	}
}

func (r *Recorder) Record(in RecordInput) (map[string]any, error) {
	ts := isoNow()
	r.mu.Lock()
	defer r.mu.Unlock()
	enforced := true
	if in.Enforced != nil {
		enforced = *in.Enforced
	}
	var policyIDs any
	if in.PolicyIDs != nil {
		policyIDs = in.PolicyIDs
	}
	payload := obj(
		"timestamp", ts,
		"agent_id", r.cfg.AgentID,
		"on_behalf_of", in.OnBehalfOf,
		"risk_tier", in.RiskTier,
		"method", in.Method,
		"path", in.Path,
		"request_body", in.RequestBody,
		"decision", in.Decision,
		"policy_id", in.PolicyID,
		"reason", in.Reason,
		"latency_ms", in.LatencyMs,
	)
	rh, err := rowHash(r.prevHash, payload)
	if err != nil {
		return nil, err
	}
	record := obj(
		"replica_id", r.replica,
		"timestamp", ts,
		"on_behalf_of", in.OnBehalfOf,
		"risk_tier", in.RiskTier,
		"method", in.Method,
		"path", in.Path,
		"host", in.Host,
		"decision", in.Decision,
		"policy_id", in.PolicyID,
		"policy_ids", policyIDs,
		"reason", in.Reason,
		"redactions", in.Redactions,
		"latency_ms", in.LatencyMs,
		"enforced", enforced,
		"call_site", in.CallSite,
		"sdk_version", Version,
		"prev_hash", r.prevHash,
		"row_hash", rh,
	)
	text, err := pyDumps(record, jsonDefault)
	if err != nil {
		return nil, err
	}
	res, err := r.db.Exec("INSERT INTO decisions (record_json, row_hash, pushed) VALUES (?,?,0)", text, rh)
	if err != nil {
		return nil, err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	record.set("seq", seq)
	r.prevHash = rh
	return record.plain(), nil
}

func (r *Recorder) PendingCount() (int, error) {
	var n int
	err := r.db.QueryRow("SELECT COUNT(*) AS n FROM decisions WHERE pushed = 0").Scan(&n)
	return n, err
}

func (r *Recorder) ChainSeq() (int64, error) {
	var s sql.NullInt64
	err := r.db.QueryRow("SELECT MAX(seq) AS s FROM decisions").Scan(&s)
	if err != nil {
		return 0, err
	}
	return s.Int64, nil
}

func (r *Recorder) Flush() (int, error) { return r.flush(nil) }

func (r *Recorder) FlushWith(client *http.Client) (int, error) { return r.flush(client) }

func (r *Recorder) flush(client *http.Client) (int, error) {
	if r.closed.Load() {
		return 0, nil
	}
	type row struct {
		seq  int64
		json string
	}
	var rows []row
	err := func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		q, err := r.db.Query("SELECT seq, record_json FROM decisions WHERE pushed = 0 ORDER BY seq ASC")
		if err != nil {
			return err
		}
		defer q.Close()
		for q.Next() {
			var x row
			if err := q.Scan(&x.seq, &x.json); err != nil {
				return err
			}
			rows = append(rows, x)
		}
		return q.Err()
	}()
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	decisions := make([]any, 0, len(rows))
	for _, x := range rows {
		v, err := pyLoads(x.json)
		if err != nil {
			return 0, err
		}
		rec, ok := v.(*jsonObject)
		if !ok {
			return 0, pyTypeError(fmt.Sprintf("'%s' object does not support item assignment", pyTypeName(v)))
		}
		rec.set("seq", x.seq)
		decisions = append(decisions, rec)
	}
	url := fmt.Sprintf("%s/api/v1/agents/%s/%s/decisions", r.cfg.CPURL, r.tenant, r.cfg.AgentID)
	own := client == nil
	c := clientOrDefault(client, flushTimeout)
	body, err := httpxJSONBody(obj("dp_id", DPID, "decisions", decisions))
	if err != nil {
		closeIfOwned(own, c)
		return 0, err
	}
	resp, err := pyDo(c, "POST", url, map[string]string{
		"Authorization": "Bearer " + r.cfg.RuntimeKey,
		"Content-Type":  "application/json",
	}, body, flushTimeout)
	if err == nil {
		err = resp.raiseForStatus()
	}
	closeIfOwned(own, c)
	if err != nil {
		if isHTTPError(err) {
			return 0, nil
		}
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare("UPDATE decisions SET pushed = 1 WHERE seq = ?")
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	for _, x := range rows {
		if _, err := stmt.Exec(x.seq); err != nil {
			stmt.Close()
			_ = tx.Rollback()
			return 0, err
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (r *Recorder) Close() error {
	r.closed.Store(true)
	r.stopOnce.Do(func() { close(r.stop) })
	if r.done != nil {
		select {
		case <-r.done:
		case <-time.After(2 * time.Second):
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.db.Close()
}

func (r *Recorder) flusherAlive() bool {
	if r.done == nil {
		return false
	}
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}
