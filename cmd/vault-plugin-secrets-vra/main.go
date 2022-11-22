package main

import (
	vra "github.com/hashicorp/vault-guides/plugins/vault-plugin-secrets-mock"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
	"os"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: vra.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		//logger := hclog.New(&hclog.LoggerOptions{})
		//logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
