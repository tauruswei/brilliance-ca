package verifier

import (
	"fmt"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/4/1 下午3:27
 */

// 只有硬国密 tls 和 预言机 才会用到
type BccspCryptoVerifier struct {
	CSP bccsp.BCCSP
	key bccsp.Key
}

// Verifier for the given BCCSP instance and key.
func New(csp bccsp.BCCSP, key bccsp.Key) (*BccspCryptoVerifier, error) {
	// Validate arguments
	if csp == nil {
		return nil, errors.New("bccsp instance must be different from nil.")
	}

	return &BccspCryptoVerifier{csp, key}, nil
}

//签名
func (s *BccspCryptoVerifier) Sign(key interface{}, digest []byte) ([]byte, error) {
	switch key.(type) {
	case []uint8:
		priKey, err := s.CSP.GetKey(key.([]uint8))
		if err != nil {
			return nil, fmt.Errorf("verifier: get key error: %s", err.Error())
		}
		s.key = priKey
	}
	return s.CSP.Sign(s.key, digest, nil)
}

//验签
func (s *BccspCryptoVerifier) Verify(key interface{}, sig []byte, digest []byte) (bool, error) {
	switch key.(type) {
	case []uint8:
		priKey, err := s.CSP.GetKey(key.([]uint8))
		if err != nil {
			return false, fmt.Errorf("verifier: get key error: %s", err.Error())
		}
		s.key = priKey
	}
	return s.CSP.Verify(s.key, sig, digest, nil)
}
