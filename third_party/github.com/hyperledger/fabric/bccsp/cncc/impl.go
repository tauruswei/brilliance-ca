package cncc

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/op/go-logging"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
	"github.com/tauruswei/go-netsign/netsign"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"golang.org/x/crypto/sha3"
	"hash"
	"strconv"
	"strings"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/15 上午11:29
 */

var (
	logger            = logging.MustGetLogger("cncc_gm")
	SessionCacheSize  = 5
	BJ_NetSignConfig  []*NetSignConfig
	SH_NetSignConfig  []*NetSignConfig
	BAK_NetSignConfig []*NetSignConfig

	KeyPrefix = "Baas"
)

type NetSignConfig struct {
	Ip     string
	Port   string
	Passwd string
}
type NetSignSesssion struct {
	NSC       *NetSignConfig
	NS_sesion int
}

type Impl struct {
	bccsp.BCCSP // 内嵌BCCSP接口

	conf *config        // conf配置
	ks   bccsp.KeyStore // key存储对象，用于存储及获取key

	netsign  *netsign.NetSign      // 签名服务器实例
	Sessions chan *NetSignSesssion // 会话标识符通道，默认5（sessionCacheSize = 5）

	noPrivImport bool // 是否禁止导入私钥
	softVerify   bool // 是否以软件方式验证签名

}

func New(opts CNCC_GMOpts, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(opts.SecLevel, opts.HashFamily)
	if err != nil {
		return nil, fmt.Errorf("Failed initializing configuration [%s]", err)
	}

	swCSP, err := sw.New(keyStore)
	if err != nil {
		return nil, fmt.Errorf("Failed initializing fallback SW BCCSP [%s]", err)
	}

	// Check KeyStore
	if keyStore == nil {
		return nil, errors.New("Invalid bccsp.KeyStore instance. It must be different from nil.")
	}

	FindPKCS11Lib(opts)

	sessions := make(chan *NetSignSesssion, SessionCacheSize)
	NetSign := netsign.NetSign{}
	var ok bool
	// 初始化 SessionCacheSize 个会话句柄
	for i := 0; i < SessionCacheSize; i++ {

		for _, netSignConfig := range BJ_NetSignConfig {

			ip := netSignConfig.Ip
			passwd := netSignConfig.Passwd

			port, err := strconv.Atoi(netSignConfig.Port)
			if err != nil {
				panic("Get port error !")
			}
			socketFd, ret := NetSign.OpenNetSign(ip, passwd, port)
			if ret != 0 {
				logger.Errorf("LOGGER-CONN-SIGNAGENT-FAIL: open netsign err: ip [%s], port [%d], passwd [%s]", ip, port,
					passwd)
				continue
			}
			sessions <- &NetSignSesssion{netSignConfig, socketFd}
			ok = true
			break
		}
	}
	// 如果 本数据中心的签名服务器链接不上，会链接其他中心的签名服务器
	if len(sessions) == 0 {
		// 初始化  SessionCacheSize 个会话句柄
		for i := 0; i < SessionCacheSize; i++ {

			for _, netSignConfig := range SH_NetSignConfig {

				ip := netSignConfig.Ip
				passwd := netSignConfig.Passwd

				port, err := strconv.Atoi(netSignConfig.Port)
				if err != nil {
					panic("Get port error !")
				}
				socketFd, ret := NetSign.OpenNetSign(ip, passwd, port)
				if ret != 0 {
					logger.Errorf("LOGGER-CONN-SIGNAGENT-FAIL: open netsign err: ip [%s], port [%d], passwd [%s]", ip, port, passwd)
					continue
				}
				sessions <- &NetSignSesssion{netSignConfig, socketFd}
				ok = true
				break
			}
		}
	}

	if !ok {
		return nil, errors.New("no netsign avaliable!")
	}
	csp := &Impl{swCSP, conf, keyStore, &NetSign, sessions, opts.Sensitive, opts.SoftVerify}
	return csp, nil
}

//上传证书
func (csp *Impl) Uploadcert(ski []byte, certBytes []byte) error {
	replace1 := strings.Replace(string(certBytes), "-----BEGIN CERTIFICATE-----", "", -1)
	replace2 := strings.Replace(replace1, "-----END CERTIFICATE-----", "", -1)
	replace := strings.Replace(replace2, "\n", "", -1)
	return csp.uploadCert(ski, []byte(replace))
}

//根据key生成选项opts生成一个key
func (csp *Impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}

	// Parse algorithm
	switch opts.(type) {
	case *bccsp.GMSM2KeyGenOpts:
		ski, pub, err := csp.generateSM2Key(opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating sm2 key")
		}
		k = &gmsm2PrivateKey{ski, gmsm2PublicKey{ski, pub}}
	case *bccsp.GMSM4KeyGenOpts:
		// todo
		ski, pub, err := csp.generateSM2Key(opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating sm4 key")
		}
		k = &gmsm2PrivateKey{ski, gmsm2PublicKey{ski, pub}}
	default:
		return nil, errors.New("Key type not recognized. Supported keys: [SM2]")
	}
	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	} else {
		csp.deleteKeyPair(k.SKI())
	}

	return k, nil
}

//根据key导入选项opts从一个key原始的数据中导入一个key
func (csp *Impl) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. Cannot be nil")
	}

	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}
	switch opts.(type) {
	case *bccsp.X509PublicKeyImportOpts:
		sm2Cert, ok := raw.(*sm2.Certificate)
		if !ok {
			return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
		}

		pk := sm2Cert.PublicKey
		switch pk.(type) {
		case sm2.PublicKey:
			logger.Infof("bccsp CNCC_GM keyimport pk is sm2.PublicKey")
			sm2PublickKey, ok := pk.(sm2.PublicKey)
			if !ok {
				return nil, errors.New("Parse interface []  to sm2 pk error")
			}
			der, err := sm2.MarshalSm2PublicKey(&sm2PublickKey)

			if err != nil {
				return nil, errors.New("MarshalSm2PublicKey error")
			}

			gmsm2SK, err := sm2.ParseSm2PublicKey(der)
			if err != nil {
				return nil, fmt.Errorf("Failed converting to GMSM2 public key [%s]", err)
			}

			logger.Infof("SKI [%s]", string(sm2Cert.SubjectKeyId))
			return &gmsm2PublicKey{sm2Cert.SubjectKeyId, gmsm2SK}, err

		case *sm2.PublicKey:
			logger.Infof("bccsp CNCC_GM keyimport pk is *sm2.PublicKey")
			sm2PublickKey, ok := pk.(*sm2.PublicKey)
			if !ok {
				return nil, errors.New("Parse interface []  to sm2 pk error")
			}
			der, err := sm2.MarshalSm2PublicKey(sm2PublickKey)
			if err != nil {
				return nil, errors.New("MarshalSm2PublicKey error")
			}
			gmsm2SK, err := sm2.ParseSm2PublicKey(der)
			if err != nil {
				return nil, fmt.Errorf("Failed converting to GMSM2 public key [%s]", err)
			}
			return &gmsm2PublicKey{sm2Cert.SubjectKeyId, gmsm2SK}, err
		default:
			return nil, errors.New("Key type not recognized. Supported keys: [SM2]")
		}
	case *bccsp.GMSM2PrivateKeyImportOpts:
		logger.Infof("bccsp CNCC_GM keyimport pk is sm2.PrivateKey")
		ski, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("[GMSM2PrivateKeyImportOpts] Invalid raw material. Expected byte array.")
		}
		//通过ski来获取私钥
		pub, isPriv, err := csp.getSM2Key(ski)
		if err == nil {
			if isPriv {
				logger.Info("Get sm2 PrivateKey in HSM")
				return &gmsm2PrivateKey{ski, gmsm2PublicKey{ski, pub}}, nil
			} else {
				logger.Info("Get sm2 PublicKey in HSM")
				return &gmsm2PublicKey{ski, pub}, nil
			}
		} else {
			return nil, fmt.Errorf("Failed converting to SM2 key [%s]", err)
		}
	default:
		return nil, errors.New("Import Key Options not recognized")
	}
}

//根据哈希选项opts哈希一个消息msg，如果opts为空，则使用默认选项
func (csp *Impl) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	hash := sm3.New()
	hash.Write(msg)
	return hash.Sum(nil), nil
	//return csp.hash(msg)
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil then the default hash function is returned.
func (csp *Impl) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	if opts == nil {
		return csp.conf.hashFunction(), nil
	}
	switch opts.(type) {
	case *bccsp.SHAOpts:
		return csp.conf.hashFunction(), nil
	case *bccsp.SHA256Opts:
		return sha256.New(), nil
	case *bccsp.SHA384Opts:
		return sha512.New384(), nil
	case *bccsp.SHA3_256Opts:
		return sha3.New256(), nil
	case *bccsp.SHA3_384Opts:
		return sha3.New384(), nil
	case *bccsp.GMSM3Opts:
		return sm3.New(), nil
		//return nil, errors.New("Usage: bccsp.Hash(msg, &bccsp.SM3Opts{})")
	default:
		return nil, fmt.Errorf("Algorithm not recognized [%s]", opts.Algorithm())
	}
}

//根据SKI返回与该接口实例有联系的key
func (csp *Impl) GetKey(ski []byte) (k bccsp.Key, err error) {

	pub, isPriv, err := csp.getSM2Key(ski)

	if err != nil {
		return nil, errors.Wrapf(err, "Failed getting key for SKI [%v]", ski)
	}

	if isPriv {
		logger.Info("Get sm2 PrivateKey in HSM")
		return &gmsm2PrivateKey{ski, gmsm2PublicKey{ski, pub}}, nil
	} else {
		logger.Info("Get sm2 PublicKey in HSM")
		return &gmsm2PublicKey{ski, pub}, nil
	}
}

//根据鉴定者选项opts，通过对比k和digest，鉴定签名
func (csp *Impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty.")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty.")
	}

	//var sig SM2Signature
	//_, err = asn1.Unmarshal(signature, &sig)

	switch k.(type) {
	case *gmsm2PrivateKey:

		//puk := k.(*gmsm2PrivateKey).pubKey.pubKey

		//verify := sm2.Verify(puk, digest, sig.R, sig.S)
		//logger.Infof("soft label [%s]\n", "SM2SignKey"+string(k.SKI()))
		return csp.verifyP11SM2(k.SKI(), digest, signature)
	case *gmsm2PublicKey:
		//puk := k.(*gmsm2PublicKey).pubKey

		//verify := sm2.Verify(puk, digest, sig.R, sig.S)
		//logger.Infof("soft label [%s]\n", "SM2SignKey"+string(k.SKI()))
		return csp.verifyP11SM2(k.SKI(), digest, signature)
	default:
		return false, errors.New("Key type not recognized. Supported keys: [SM2 Key]")
	}
}

//根据签名者选项opts，使用k对digest进行签名，注意如果需要对一个特别大的消息的hash值
//进行签名，调用者则负责对该特别大的消息进行hash后将其作为digest传入
func (csp *Impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	// Parse algorithm
	switch k.(type) {
	case *gmsm2PrivateKey:
		//r, s, err := csp.signP11SM2(k.SKI(), digest)
		//if err != nil {
		//	return nil, err
		//}
		return csp.signP11SM2(k.SKI(), digest)
	default:
		return nil, errors.New("Key type not recognized. Supported keys: [SM2 Private Key]")
	}

	return
}

//根据加密者选项opts，使用k加密plaintext
func (csp *Impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	//// Validate arguments
	//if k == nil {
	//	return nil, errors.New("Invalid Key. It must not be nil.")
	//}
	//
	//encryptor, found := csp.encryptors[reflect.TypeOf(k)]
	//if !found {
	//	return nil, errors.Errorf("Unsupported 'EncryptKey' provided [%v]", k)
	//}
	//
	//return encryptor.Encrypt(k, plaintext, opts)
	// todo
	return nil, nil
}

//根据解密者选项opts，使用k对ciphertext进行解密
func (csp *Impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	//// Validate arguments
	//if k == nil {
	//	return nil, errors.New("Invalid Key. It must not be nil.")
	//}
	//
	//decryptor, found := csp.decryptors[reflect.TypeOf(k)]
	//if !found {
	//	return nil, errors.Errorf("Unsupported 'DecryptKey' provided [%v]", k)
	//}
	//
	//plaintext, err = decryptor.Decrypt(k, ciphertext, opts)
	//if err != nil {
	//	return nil, errors.Wrapf(err, "Failed decrypting with opts [%v]", opts)
	//}
	//
	//return
	// todo
	return nil, nil
}

//根据解密者选项opts，使用k对ciphertext进行解密
func (csp *Impl) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	//// Validate arguments
	//if k == nil {
	//	return nil, errors.New("Invalid Key. It must not be nil.")
	//}
	//
	//decryptor, found := csp.decryptors[reflect.TypeOf(k)]
	//if !found {
	//	return nil, errors.Errorf("Unsupported 'DecryptKey' provided [%v]", k)
	//}
	//
	//plaintext, err = decryptor.Decrypt(k, ciphertext, opts)
	//if err != nil {
	//	return nil, errors.Wrapf(err, "Failed decrypting with opts [%v]", opts)
	//}
	//
	//return
	// todo
	return nil, nil
}
