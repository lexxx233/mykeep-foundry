// Package host is the Go side of Foundry's capability ABI: it turns a tool's foundry.*
// calls into brokered, capability-enforced operations against the encrypted store (and,
// from M4, the network and Vault). Enforcement lives here — the JS sandbox is never
// trusted to limit itself. Each invocation gets a Dispatcher bound to the tool's grant
// (its storage namespace, and later its allowed hosts/credentials).
package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"mykeep.ai/foundry/internal/jsengine"
	"mykeep.ai/foundry/internal/store"
)

// VaultFiller is the by-reference Vault seam: it makes an authenticated request AS the
// user without ever revealing the secret to Foundry or the tool. The suite injects a real
// filler (routing to the Vault component); standalone Foundry leaves it nil.
type VaultFiller interface {
	Fetch(ctx context.Context, credential string, req VaultReq) (VaultResp, error)
}

// VaultReq / VaultResp are the by-reference request/response (no secret crosses them).
type VaultReq struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}
type VaultResp struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// Config is one tool invocation's capability grant + the brokers that enforce it.
type Config struct {
	Store      *store.Store
	Namespace  string      // storage namespace
	AllowHosts []string    // network grant (exact hosts or ".suffix")
	VaultCreds []string    // credential names the tool may use by reference
	Broker     *Broker     // HTTP egress broker (nil = no network)
	Vault      VaultFiller // by-reference Vault (nil = unavailable)
}

// Dispatcher brokers one tool invocation's host calls.
type Dispatcher struct {
	cfg Config
}

// New binds a dispatcher to a tool's capability grant.
func New(cfg Config) *Dispatcher { return &Dispatcher{cfg: cfg} }

// HostFunc adapts the dispatcher to the jsengine host ABI.
func (d *Dispatcher) HostFunc() jsengine.HostFunc { return d.Call }

// Call executes one host op. Unknown ops error (the tool sees a thrown exception).
func (d *Dispatcher) Call(ctx context.Context, op string, args json.RawMessage) (json.RawMessage, error) {
	switch op {
	case "echo": // M1 probe, harmless to keep
		return args, nil

	case "kv.get":
		var a struct{ Key string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		v, ok, err := d.cfg.Store.KVGet(d.cfg.Namespace, a.Key)
		return orNull(v, ok), err
	case "kv.set":
		var a struct {
			Key   string
			Value json.RawMessage
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		return jnull, d.cfg.Store.KVSet(d.cfg.Namespace, a.Key, valueBytes(a.Value))
	case "kv.del":
		var a struct{ Key string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		return jnull, d.cfg.Store.KVDel(d.cfg.Namespace, a.Key)

	case "queue.push":
		var a struct {
			Name string
			Msg  json.RawMessage
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		return jnull, d.cfg.Store.QueuePush(d.cfg.Namespace, a.Name, valueBytes(a.Msg))
	case "queue.pop":
		var a struct{ Name string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		v, ok, err := d.cfg.Store.QueuePop(d.cfg.Namespace, a.Name)
		return orNull(v, ok), err

	case "cache.get":
		var a struct{ Key string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		v, ok, err := d.cfg.Store.CacheGet(d.cfg.Namespace, a.Key)
		return orNull(v, ok), err
	case "cache.set":
		var a struct {
			Key        string
			Value      json.RawMessage
			TTLSeconds float64 `json:"ttl_seconds"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		return jnull, d.cfg.Store.CacheSet(d.cfg.Namespace, a.Key, valueBytes(a.Value), time.Duration(a.TTLSeconds*float64(time.Second)))

	case "blob.put":
		var a struct {
			Name string
			Data string // base64
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(a.Data)
		if err != nil {
			return nil, fmt.Errorf("blob.put: data must be base64: %w", err)
		}
		return jnull, d.cfg.Store.BlobPut(d.cfg.Namespace, a.Name, raw)
	case "blob.get":
		var a struct{ Name string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		v, ok, err := d.cfg.Store.BlobGet(d.cfg.Namespace, a.Name)
		if err != nil || !ok {
			return jnull, err
		}
		return json.Marshal(base64.StdEncoding.EncodeToString(v))

	case "http.fetch":
		if d.cfg.Broker == nil {
			return nil, fmt.Errorf("network not available")
		}
		var fr fetchReq
		if err := json.Unmarshal(args, &fr); err != nil {
			return nil, err
		}
		resp, err := d.cfg.Broker.fetch(ctx, d.cfg.AllowHosts, fr)
		if err != nil {
			return nil, err
		}
		return json.Marshal(resp)

	case "vault.fetch":
		if d.cfg.Vault == nil {
			return nil, fmt.Errorf("vault not configured")
		}
		var a struct {
			Credential string            `json:"credential"`
			Method     string            `json:"method"`
			URL        string            `json:"url"`
			Headers    map[string]string `json:"headers"`
			Body       string            `json:"body"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		if !contains(d.cfg.VaultCreds, a.Credential) {
			return nil, fmt.Errorf("credential not granted: %s", a.Credential)
		}
		resp, err := d.cfg.Vault.Fetch(ctx, a.Credential, VaultReq{Method: a.Method, URL: a.URL, Headers: a.Headers, Body: a.Body})
		if err != nil {
			return nil, err
		}
		return json.Marshal(resp)

	default:
		return nil, fmt.Errorf("unknown or ungranted op: %s", op)
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

var jnull = json.RawMessage("null")

// valueBytes stores a JS value as its JSON bytes (defaulting to JSON null).
func valueBytes(v json.RawMessage) []byte {
	if len(v) == 0 {
		return []byte("null")
	}
	return []byte(v)
}

// orNull returns the stored JSON value, or JSON null when absent.
func orNull(v []byte, ok bool) json.RawMessage {
	if !ok {
		return jnull
	}
	return json.RawMessage(v)
}
