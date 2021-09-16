package util

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/brilliance/ca/common/config"
	logger "github.com/brilliance/ca/common/log"
	"github.com/brilliance/ca/model"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"hash"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

var sha256Hash hash.Hash = sha256.New()

func GetSha256Code(s string) string {
	sha256Hash.Reset()
	sha256Hash.Write([]byte(s))
	return fmt.Sprintf("%x", sha256Hash.Sum(nil))
}

// ========== AES CBC ===========
// AES CBC模式加密
func AESEncryptCBC(origData []byte, key []byte) (encrypted []byte) {
	// 分组密钥
	// NewCipher该函数限制了输入key的长度必须为16、24、32,分别对应AES-128、AES-192、AES-256
	block, err := aes.NewCipher(key) // 分组密钥
	if err != nil {
		logger.Errorf("aes encrypt error: %s", err.Error())
		return nil
	}
	blockSize := block.BlockSize()                              // 获取密钥块的长度
	origData = pkcs5Padding(origData, blockSize)                // 补全码
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) // 加密模式 iv: key[:blockSize]
	encrypted = make([]byte, len(origData))                     //创建数组
	blockMode.CryptBlocks(encrypted, origData)                  // 加密
	return encrypted
}

// AES CBC模式解密
func AESDencryptCBC(encrypted []byte, key []byte) (decrypted []byte) {
	block, err := aes.NewCipher(key) // 分组密钥
	if err != nil {
		logger.Errorf("aes dencrypt error: %s", err.Error())
		return nil
	}
	blockSize := block.BlockSize()                              // 获取密钥块长度
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) //加密模式
	decrypted = make([]byte, len(encrypted))                    // 创建数组
	blockMode.CryptBlocks(decrypted, encrypted)                 // 解密
	decrypted = pkcs5Unpadding(decrypted)                       // 去除补全码
	return decrypted
}

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs5Unpadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// 根据密钥和连接进行AES加密
func AESEncryptConnection(key string, conn string) (keyBase64 string, connBase64 string) {
	if len(key) == 0 || len(conn) == 0 {
		logger.Error("连接和密钥不能为空")
		return
	}
	// 密钥base64加密
	keyBase64 = base64.StdEncoding.EncodeToString([]byte(key))
	hash := GetSha256Code(key)                                // 密钥进行hash
	realKey := hash[:32]                                      // 取hash之后的前32位作为获得真正的密钥
	encrypted := AESEncryptCBC([]byte(conn), []byte(realKey)) // 加密
	connBase64 = base64.StdEncoding.EncodeToString(encrypted) // 对加密后的数据再进行base64加密
	return
}

// 根据传进来的私钥和连接(加密后的)解密(AES)得到真正的连接
func AESDecryptConnection(keyBase64 string, connBase64 string) string {
	if len(keyBase64) == 0 || len(connBase64) == 0 {
		logger.Error("连接和密钥不能为空")
		return ""
	}
	originKey, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		logger.Errorf("解析密钥失败：%s", err.Error())
		panic(err)
	}
	originConn, err := base64.StdEncoding.DecodeString(connBase64)
	if err != nil {
		logger.Errorf("解析数据库连接失败,Err：%s", err.Error())
		panic(err)
	}
	hash := GetSha256Code(string(originKey))                     // 获得密钥的hash
	realKey := hash[:32]                                         // 取hash的前32位为真正的密钥
	decryptedConn := AESDencryptCBC(originConn, []byte(realKey)) //解密数据库连接
	if decryptedConn == nil {
		logger.Error("解析数据库连接失败")
		panic("解析数据库连接失败")
	}
	return string(decryptedConn)
}

// LoadPrivateKey loads a private key from file in keystorePath
func LoadPrivateKey(keystorePath string) (string, error) {
	var err error

	var rawKey string

	walkFunc := func(path string, info os.FileInfo, err error) error {
		rawKeyByte, err := ioutil.ReadFile(path)
		if strings.HasSuffix(path, "_sk") {
			if err != nil {
				logger.Error(GetErrorStackf(err, "读取密钥失败: path = %s", path))
				return errors.WithMessagef(err, "读取密钥失败: path = %s", path)
			}
			rawKey = string(rawKeyByte)
		}
		return nil
	}

	err = filepath.Walk(keystorePath, walkFunc)
	if err != nil {
		logger.Error(GetErrorStackf(err, "读取密钥失败: keystorePath = %s", keystorePath))
		return "", errors.WithMessagef(err, "读取密钥失败: keystorePath = %s", keystorePath)
	}

	return rawKey, err
}

func ImportPrivateKey(keySize int, key, provider, cryptoType, keyStore string) (priv bccsp.Key, s crypto.Signer,
	err error) {
	//// 生成临时目录
	//keyStore = MakeTempdir()
	//defer os.RemoveAll(keyStore)
	csp, err := config.GetBCCSP(provider, "SHA2", 256)
	if err != nil {
		logger.Error(GetErrorStack(err, "获取 bccsp 实例失败"))
		return nil, nil, errors.WithMessage(err, "获取 bccsp 实例失败")
	}
	block, _ := pem.Decode([]byte(key))

	switch strings.ToUpper(cryptoType) {
	case "ECC":
		priv, err = csp.KeyImport(block.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: false})
	case "SM2":
		priv, err = csp.KeyImport(block.Bytes, &bccsp.GMSM2PrivateKeyImportOpts{Temporary: false})
	default:
		logger.Error(GetErrorStackf(err, "不支持的算法：%s", cryptoType))
		return nil, nil, errors.WithMessagef(err, "不支持的算法：%s", cryptoType)
	}

	if err == nil {
		s, err = signer.New(csp, priv)
		if err != nil {
			logger.Error(GetErrorStack(err, "构建 crypto signer 失败"))
			return nil, nil, errors.WithMessage(err, "构建 crypto signer 失败")

		}
	}
	return
}

func ImportPublicKey(keySize int, key, provider, cryptoType, keyStore string) (priv bccsp.Key, err error) {
	// 生成临时目录
	//keyStore = MakeTempdir()
	//defer os.RemoveAll(keyStore)
	csp, err := config.GetBCCSP(provider, "SHA2", 256)
	if err != nil {
		logger.Error(GetErrorStack(err, "获取 bccsp 实例失败"))
		return nil, errors.WithMessage(err, "获取 bccsp 实例失败")
	}

	block, _ := pem.Decode([]byte(key))

	//switch strings.ToUpper(cryptoType) {
	//case "ECC":
	//	priv, err = csp.KeyImport(block.Bytes,&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: false})
	//case "SM2":
	//	priv, err = csp.KeyImport(block.Bytes,&bccsp.GMSM2PublicKeyImportOpts{Temporary: false})
	//default:
	//	logger.Error(util.GetErrorStackf(err, "不支持的算法：%s", cryptoType))
	//	return nil, nil, errors.WithMessagef(err, "不支持的算法：%s", cryptoType)
	//}
	return csp.KeyImport(block.Bytes, &bccsp.X509PublicKeyImportOpts{Temporary: false})
}

// default template for X509 certificates
func X509Template(request *model.CertificateRequest) x509.Certificate {

	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// set expiry to around 10 years
	expiry := time.Duration(request.Period) * time.Hour
	// round minute and backdate 5 minutes
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute)

	//basic template to use
	x509 := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry),
		BasicConstraintsValid: true,
	}
	return x509
}

// Additional for X509 subject
func SubjectTemplateAdditional(commonName, org, country, province, locality, orgUnit, streetAddress, postalCode string) pkix.Name {
	name := SubjectTemplate()
	name.CommonName = commonName
	if len(org) >= 1 {
		name.Organization = []string{org}
	}
	if len(country) >= 1 {
		name.Country = []string{country}
	}
	if len(province) >= 1 {
		name.Province = []string{province}
	}

	if len(locality) >= 1 {
		name.Locality = []string{locality}
	}
	if len(orgUnit) >= 1 {
		name.OrganizationalUnit = []string{orgUnit}
	}
	if len(streetAddress) >= 1 {
		name.StreetAddress = []string{streetAddress}
	}
	if len(postalCode) >= 1 {
		name.PostalCode = []string{postalCode}
	}
	return name
}

// default template for X509 subject
func SubjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}

func GenCertificate(request model.CertificateRequest, priv bccsp.Key, s crypto.Signer, subject pkix.Name,
	ku x509.KeyUsage, eku []x509.ExtKeyUsage, cryptoType string) ([]byte, error) {
	//priv, signer, err := GenPrivateKey(request)
	//if err != nil {
	//	return nil, err
	//}
	csr, err := GenCertificateSignRequest(&request, priv, subject, ku, eku, cryptoType)

	if err != nil {
		logger.Error(GetErrorStackf(err, "构建证书请求失败：%+v", request))
		return nil, errors.WithMessagef(err, "构建证书请求失败：%+v", request)
	}
	switch strings.ToUpper(cryptoType) {
	case "ECC":
		return x509.CreateCertificate(rand.Reader, csr.(*x509.Certificate), csr.(*x509.Certificate),
			(csr.(*x509.Certificate)).PublicKey.(*ecdsa.PublicKey), s)
	case "SM2":
		return sm2.CreateCertificateToMem(csr.(*sm2.Certificate), csr.(*sm2.Certificate),
			(csr.(*sm2.Certificate)).PublicKey.(*sm2.PublicKey), s)
	}
	return nil, nil
}

func GenPrivateKey(keySize int, provider, cryptoType, keyStore string) (priv bccsp.Key, s crypto.Signer, err error) {

	csp, err := config.GetBCCSP(provider, "SHA2", 256)
	if err != nil {
		logger.Error(GetErrorStack(err, "获取 bccsp 实例失败"))
		return nil, nil, errors.WithMessage(err, "获取 bccsp 实例失败")
	}

	switch strings.ToUpper(cryptoType) {
	case "ECC":
		switch keySize {
		case 256:
			priv, err = csp.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: false})
		case 384:
			priv, err = csp.KeyGen(&bccsp.ECDSAP384KeyGenOpts{Temporary: false})
		default:
			logger.Error(GetErrorStackf(err, "不支持的 ecdsa 算法长度：%d", keySize))
			return nil, nil, errors.WithMessagef(err, "不支持的 ecdsa 算法长度：%d", keySize)
		}
	case "SM2":
		priv, err = csp.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	default:
		logger.Error(GetErrorStackf(err, "不支持的算法：%s", cryptoType))
		return nil, nil, errors.WithMessagef(err, "不支持的算法：%s", cryptoType)
	}
	if err != nil {
		logger.Error(GetErrorStackf(err, "生成密钥失败：CryptoType = %s, KeySize = %d", cryptoType, keySize))
		return nil, nil, errors.WithMessagef(err, "生成密钥失败：CryptoType = %s, KeySize = %d", cryptoType, keySize)
	}

	if err == nil {
		s, err = signer.New(csp, priv)
		if err != nil {
			logger.Error(GetErrorStack(err, "构建 crypto signer 失败"))
			return nil, nil, errors.WithMessage(err, "构建 crypto signer 失败")

		}
	}
	return
}

func GenCertificateSignRequest(request *model.CertificateRequest, priv bccsp.Key, subject pkix.Name,
	ku x509.KeyUsage, eku []x509.ExtKeyUsage, cryptoType string) (interface{}, error) {
	var err error
	var pubKey interface{}
	template := X509Template(request)
	template.IsCA = true
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	//subject := subjectTemplateAdditional(request.CommonName,request.Org,request.Country,request.Province, request.Locality, request.OrgUnit,
	//	request.StreetAddress,request.PostalCode)

	template.Subject = subject
	template.SubjectKeyId = priv.SKI()
	switch strings.ToUpper(cryptoType) {
	case "ECC":
		pubKey, err = csp.GetECPublicKey(priv)
		if err != nil {
			logger.Error(GetErrorStackf(err, "获取 ecdsa public key 失败：%s", err.Error()))
			return nil, errors.Errorf("获取 ecdsa public key 失败：%s", err.Error())
		}
		template.PublicKey = pubKey
		return template, nil
	case "SM2":
		pubKey, err = csp.GetSM2PublicKey(priv)
		if err != nil {
			logger.Error(GetErrorStackf(err, "获取 sm2 public key 失败：%s", err.Error()))
			return nil, errors.Errorf("获取 sm2 public key 失败：%s", err.Error())
		}
		sm2Template := gm.ParseX509Certificate2Sm2(&template)
		sm2Template.PublicKey = pubKey
		return sm2Template, nil
	}
	return nil, nil
}

func CopyFields(des interface{}, source interface{}, fields ...string) (err error) {
	at := reflect.TypeOf(des)
	av := reflect.ValueOf(des)
	bt := reflect.TypeOf(source)
	bv := reflect.ValueOf(source)

	// 简单判断下
	if at.Kind() != reflect.Ptr {
		err = fmt.Errorf("a must be a struct pointer")
		return
	}
	av = reflect.ValueOf(av.Interface())

	// 要复制哪些字段
	_fields := make([]string, 0)
	if len(fields) > 0 {
		_fields = fields
	} else {
		for i := 0; i < bv.NumField(); i++ {
			_fields = append(_fields, bt.Field(i).Name)
		}
	}

	if len(_fields) == 0 {
		fmt.Println("no fields to copy")
		return
	}

	// 复制
	for i := 0; i < len(_fields); i++ {
		name := _fields[i]
		f := av.Elem().FieldByName(name)
		bValue := bv.FieldByName(name)

		// a中有同名的字段并且类型一致才复制
		if f.IsValid() && f.Kind() == bValue.Kind() {
			f.Set(bValue)
		} else {
			fmt.Printf("no such field or different kind, fieldName: %s\n", name)
		}
	}
	return
}
