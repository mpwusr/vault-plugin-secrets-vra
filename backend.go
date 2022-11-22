package vra

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"sync"
)

// backend wraps the backend framework and adds a map for storing key value pairs
type vraBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *vraClient
}

var _ logical.Factory = Factory

// Factory configures and returns VRA backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*vraBackend, error) {
	b := &vraBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(vraHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(b),
			[]*framework.Path{
				pathConfig(b),
				pathCredentials(b),
			},
		),
		Secrets: []*framework.Secret{
			b.vraToken(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return b, nil
}

func (b *vraBackend) paths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: framework.MatchAllRegex("path"),

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "Specifies the path of the secret.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRead,
					Summary:  "Retrieve the secret from the map.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
					Summary:  "Store a secret at the specified location.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDelete,
					Summary:  "Deletes the secret at the specified location.",
				},
			},

			ExistenceCheck: b.handleExistenceCheck,
		},
	}
}

func (b *vraBackend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (b *vraBackend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)

	// Decode the data
	var rawData map[string]interface{}
	entry, err := req.Storage.Get(ctx, req.ClientToken+"/"+path)
	if err != nil {
		return nil, err
	}
	fetchedData := entry.Value
	if fetchedData == nil {
		resp := logical.ErrorResponse("No value at %v%v", req.MountPoint, path)
		return resp, nil
	}

	if err := jsonutil.DecodeJSON(fetchedData, &rawData); err != nil {
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}

	// Generate the response
	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}

func (b *vraBackend) handleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	// Check to make sure that kv pairs provided
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("data must be provided to store in secret")
	}

	path := data.Get("path").(string)

	// JSON encode the data
	buf, err := json.Marshal(req.Data)
	if err != nil {
		return nil, errwrap.Wrapf("json encoding failed: {{err}}", err)
	}

	// Store kv pairs in map at specified path
	entry := &logical.StorageEntry{
		Key:      req.ClientToken + "/" + path,
		Value:    buf,
		SealWrap: false,
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *vraBackend) handleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)

	// Remove entry for specified path
	if err := req.Storage.Delete(ctx, req.ClientToken+"/"+path); err != nil {
		return nil, err
	}

	return nil, nil
}

// reset clears any client configuration for a new
// backend to be configured
func (b *vraBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *vraBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *vraBackend) getClient(ctx context.Context, s logical.Storage) (*vraClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(vraConfig)
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}

const vraHelp = `
The VRA backend dynamically generates user tokens.
After mounting this backend, credentials to manage user tokens
must be configured with the "config/" endpoints.
`
