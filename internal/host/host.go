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

// Dispatcher brokers one tool invocation's host calls.
type Dispatcher struct {
	store *store.Store
	ns    string // the tool's storage namespace (its capability grant)
}

// New binds a dispatcher to a store and the calling tool's namespace.
func New(st *store.Store, namespace string) *Dispatcher {
	return &Dispatcher{store: st, ns: namespace}
}

// HostFunc adapts the dispatcher to the jsengine host ABI.
func (d *Dispatcher) HostFunc() jsengine.HostFunc { return d.Call }

// Call executes one host op. Unknown ops error (the tool sees a thrown exception).
func (d *Dispatcher) Call(_ context.Context, op string, args json.RawMessage) (json.RawMessage, error) {
	switch op {
	case "echo": // M1 probe, harmless to keep
		return args, nil

	case "kv.get":
		var a struct{ Key string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		v, ok, err := d.store.KVGet(d.ns, a.Key)
		return orNull(v, ok), err
	case "kv.set":
		var a struct {
			Key   string
			Value json.RawMessage
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		return jnull, d.store.KVSet(d.ns, a.Key, valueBytes(a.Value))
	case "kv.del":
		var a struct{ Key string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		return jnull, d.store.KVDel(d.ns, a.Key)

	case "queue.push":
		var a struct {
			Name string
			Msg  json.RawMessage
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		return jnull, d.store.QueuePush(d.ns, a.Name, valueBytes(a.Msg))
	case "queue.pop":
		var a struct{ Name string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		v, ok, err := d.store.QueuePop(d.ns, a.Name)
		return orNull(v, ok), err

	case "cache.get":
		var a struct{ Key string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		v, ok, err := d.store.CacheGet(d.ns, a.Key)
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
		return jnull, d.store.CacheSet(d.ns, a.Key, valueBytes(a.Value), time.Duration(a.TTLSeconds*float64(time.Second)))

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
		return jnull, d.store.BlobPut(d.ns, a.Name, raw)
	case "blob.get":
		var a struct{ Name string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		v, ok, err := d.store.BlobGet(d.ns, a.Name)
		if err != nil || !ok {
			return jnull, err
		}
		return json.Marshal(base64.StdEncoding.EncodeToString(v))

	default:
		return nil, fmt.Errorf("unknown or ungranted op: %s", op)
	}
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
