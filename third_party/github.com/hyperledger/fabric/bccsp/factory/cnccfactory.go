package factory

import (
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/cncc"
	"github.com/hyperledger/fabric/bccsp/sw"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/15 下午5:24
 */

const (
	// CNCC_GM BasedFactoryName is the name of the factory of the hsm-based BCCSP implementation
	CNCC_GMBasedFactoryName = "CNCC_GM"
)

// CNCC_GMFactory is the factory of the HSM-based BCCSP.
type CNCC_GMFactory struct{}

// Name returns the name of this factory
func (f *CNCC_GMFactory) Name() string {
	return CNCC_GMBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *CNCC_GMFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.CNCC_GMOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	p11Opts := config.CNCC_GMOpts

	//TODO: CNCC_GM does not need a keystore, but we have not migrated all of PKCS11 BCCSP to PKCS11 yet
	var ks bccsp.KeyStore
	if p11Opts.Ephemeral == true {
		ks = sw.NewDummyKeyStore()
	} else if p11Opts.FileKeystore != nil {
		fks, err := cncc.NewFileBasedKeyStore(nil, p11Opts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, fmt.Errorf("Failed to initialize software key store: %s", err)
		}
		ks = fks
	} else {
		// Default to DummyKeystore
		ks = sw.NewDummyKeyStore()
	}

	return cncc.New(*p11Opts, ks)
}
