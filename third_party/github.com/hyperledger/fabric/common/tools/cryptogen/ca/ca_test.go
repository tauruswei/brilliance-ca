/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package ca_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric/bccsp/cncc"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
	"github.com/stretchr/testify/assert"
	"github.com/tauruswei/go-netsign/netsign"
	"github.com/tjfoc/gmsm/sm2"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testCAName             = "root0"
	testCA2Name            = "root1"
	testCA3Name            = "root2"
	testName               = "cert0"
	testName2              = "cert1"
	testName3              = "cert2"
	testIP                 = "172.16.10.31"
	testCountry            = "US"
	testProvince           = "California"
	testLocality           = "San Francisco"
	testOrganizationalUnit = "Hyperledger Fabric"
	testStreetAddress      = "testStreetAddress"
	testPostalCode         = "123456"
)

var testDir = filepath.Join(os.TempDir(), "ca-test")

//func TestLoadCertificateECDSA(t *testing.T) {
//	caDir := filepath.Join(testDir, "ca")
//	certDir := filepath.Join(testDir, "certs")
//	// generate private key
//	priv, _, err := csp.GeneratePrivateKey(certDir)
//	assert.NoError(t, err, "Failed to generate signed certificate")
//
//	// get EC public key
//	//ecPubKey, err := csp.GetSM2PublicKey(priv)
//	//assert.NoError(t, err, "Failed to generate signed certificate")
//	//assert.NotNil(t, ecPubKey, "Failed to generate signed certificate")
//
//	// create our CA
//	rootCA, err := ca.NewCA(caDir, testCA3Name, testCA3Name, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode)
//	assert.NoError(t, err, "Error generating CA")
//
//	cert, err := rootCA.SignCertificate(certDir, testName3, nil, nil, priv,
//		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
//		[]x509.ExtKeyUsage{x509.ExtKeyUsageAny})
//	assert.NoError(t, err, "Failed to generate signed certificate")
//	// KeyUsage should be x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
//	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
//		cert.KeyUsage)
//	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageAny)
//
//	loadedCert, err := ca.LoadCertificateGMSM2(certDir)
//	assert.NotNil(t, loadedCert, "Should load cert")
//	assert.Equal(t, cert.SerialNumber, loadedCert.SerialNumber, "Should have same serial number")
//	assert.Equal(t, cert.Subject.CommonName, loadedCert.Subject.CommonName, "Should have same CN")
//	cleanup(testDir)
//}

func TestNewCA(t *testing.T) {
	cleanup(testDir)
	caDir := filepath.Join(testDir, "ca")
	rootCA, err := NewCA(caDir, testCAName, testCAName, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode)
	assert.NoError(t, err, "Error generating CA")
	assert.NotNil(t, rootCA, "Failed to return CA")
	assert.NotNil(t, rootCA.SignSm2Cert,
		"rootCA.Signer should not be empty")
	assert.IsType(t, &sm2.Certificate{}, rootCA.SignSm2Cert,
		"rootCA.SignCert should be type x509.Certificate")

	// check to make sure the root public key was storedll
	pemFile := filepath.Join(caDir, testCAName+"-cert.pem")
	assert.Equal(t, true, checkForFile(pemFile),
		"Expected to find file "+pemFile)

	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.Country, "country cannot be empty.")
	assert.Equal(t, testCountry, rootCA.SignSm2Cert.Subject.Country[0], "Failed to match country")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.Province, "province cannot be empty.")
	assert.Equal(t, testProvince, rootCA.SignSm2Cert.Subject.Province[0], "Failed to match province")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.Locality, "locality cannot be empty.")
	assert.Equal(t, testLocality, rootCA.SignSm2Cert.Subject.Locality[0], "Failed to match locality")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.OrganizationalUnit, "organizationalUnit cannot be empty.")
	assert.Equal(t, testOrganizationalUnit, rootCA.SignSm2Cert.Subject.OrganizationalUnit[0], "Failed to match organizationalUnit")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.StreetAddress, "streetAddress cannot be empty.")
	assert.Equal(t, testStreetAddress, rootCA.SignSm2Cert.Subject.StreetAddress[0], "Failed to match streetAddress")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.PostalCode, "postalCode cannot be empty.")
	assert.Equal(t, testPostalCode, rootCA.SignSm2Cert.Subject.PostalCode[0], "Failed to match postalCode")

}
func TestNewTlsCA(t *testing.T) {
	cleanup(testDir)
	caDir := filepath.Join(testDir, "ca")
	rootCA, err := NewCA(caDir, testCAName, testCAName, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode)
	assert.NoError(t, err, "Error generating CA")
	assert.NotNil(t, rootCA, "Failed to return CA")
	assert.NotNil(t, rootCA.SignSm2Cert,
		"rootCA.Signer should not be empty")
	assert.IsType(t, &sm2.Certificate{}, rootCA.SignSm2Cert,
		"rootCA.SignCert should be type x509.Certificate")

	// check to make sure the root public key was stored
	pemFile := filepath.Join(caDir, testCAName+"-cert.pem")
	assert.Equal(t, true, checkForFile(pemFile),
		"Expected to find file "+pemFile)

	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.Country, "country cannot be empty.")
	assert.Equal(t, testCountry, rootCA.SignSm2Cert.Subject.Country[0], "Failed to match country")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.Province, "province cannot be empty.")
	assert.Equal(t, testProvince, rootCA.SignSm2Cert.Subject.Province[0], "Failed to match province")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.Locality, "locality cannot be empty.")
	assert.Equal(t, testLocality, rootCA.SignSm2Cert.Subject.Locality[0], "Failed to match locality")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.OrganizationalUnit, "organizationalUnit cannot be empty.")
	assert.Equal(t, testOrganizationalUnit, rootCA.SignSm2Cert.Subject.OrganizationalUnit[0], "Failed to match organizationalUnit")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.StreetAddress, "streetAddress cannot be empty.")
	assert.Equal(t, testStreetAddress, rootCA.SignSm2Cert.Subject.StreetAddress[0], "Failed to match streetAddress")
	assert.NotEmpty(t, rootCA.SignSm2Cert.Subject.PostalCode, "postalCode cannot be empty.")
	assert.Equal(t, testPostalCode, rootCA.SignSm2Cert.Subject.PostalCode[0], "Failed to match postalCode")

}

func TestGenerateSignCertificate(t *testing.T) {
	cleanup(testDir)
	caDir := filepath.Join(testDir, "ca")
	certDir := filepath.Join(testDir, "certs")
	// generate private key
	priv, _, err := csp.GeneratePrivateKey(certDir)
	assert.NoError(t, err, "Failed to generate signed certificate")

	//// get EC public key
	//ecPubKey, err := csp.GetSM2PublicKey(priv)
	//assert.NoError(t, err, "Failed to generate signed certificate")
	//assert.NotNil(t, ecPubKey, "Failed to generate signed certificate")

	// create our CA
	//rootCA, err := ca.NewCA(caDir, testCA2Name, testCA2Name, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode)
	//assert.NoError(t, err, "Error generating CA")

	rootCA, err := NewCA(caDir, testCA2Name, testCA2Name, testCountry, testProvince, testLocality,
		testOrganizationalUnit, testStreetAddress, testPostalCode)
	assert.NoError(t, err, "Error generating CA")

	cert, err := rootCA.SignCertificate(certDir, testName, nil, nil, priv,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageAny})
	assert.NoError(t, err, "Failed to generate signed certificate")
	// KeyUsage should be x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	assert.Equal(t, sm2.KeyUsageDigitalSignature|sm2.KeyUsageKeyEncipherment,
		cert.KeyUsage)
	assert.Contains(t, cert.ExtKeyUsage, sm2.ExtKeyUsageAny)

	//cert, err = rootCA.SignCertificate(certDir, testName, nil, nil, priv,
	//	x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{})
	//assert.NoError(t, err, "Failed to generate signed certificate")
	//assert.Equal(t, 0, len(cert.ExtKeyUsage))
	//
	//// make sure ous are correctly set
	//ous := []string{"TestOU", "PeerOU"}
	//cert, err = rootCA.SignCertificate(certDir, testName, ous, nil, priv,
	//	x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{})
	//assert.Contains(t, cert.Subject.OrganizationalUnit, ous[0])
	//assert.Contains(t, cert.Subject.OrganizationalUnit, ous[1])
	//
	//// make sure sans are correctly set
	//sans := []string{testName2, testIP}
	//cert, err = rootCA.SignCertificate(certDir, testName, nil, sans, priv,
	//	x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{})
	//assert.Contains(t, cert.DNSNames, testName2)
	//assert.Contains(t, cert.IPAddresses, net.ParseIP(testIP).To4())
	//
	//// check to make sure the signed public key was stored
	//pemFile := filepath.Join(certDir, testName+"-cert.pem")
	//assert.Equal(t, true, checkForFile(pemFile),
	//	"Expected to find file "+pemFile)
	//
	//_, err = rootCA.SignCertificate(certDir, "empty/CA", nil, nil, priv,
	//	x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageAny})
	//assert.Error(t, err, "Bad name should fail")
	//
	//// use an empty CA to test error path
	//badCA := &ca.CA{
	//	Name:     "badCA",
	//	SignCert: &x509.Certificate{},
	//}
	//_, err = badCA.SignCertificate(certDir, testName, nil, nil, priv,
	//	x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageAny})
	//assert.Error(t, err, "Empty CA should not be able to sign")
	//cleanup(testDir)

}
func TestGenerateSignCertificate1(t *testing.T) {
	cleanup(testDir)
	caDir := filepath.Join(testDir, "ca")
	certDir := filepath.Join(testDir, "certs")
	// generate private key
	priv, _, err := csp.GeneratePrivateKey(certDir)
	assert.NoError(t, err, "Failed to generate signed certificate")

	//// get EC public key
	//ecPubKey, err := csp.GetSM2PublicKey(priv)
	//assert.NoError(t, err, "Failed to generate signed certificate")
	//assert.NotNil(t, ecPubKey, "Failed to generate signed certificate")

	//create our CA
	rootCA, err := NewCA(caDir, testCA2Name, testCA2Name, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode)
	assert.NoError(t, err, "Error generating CA")

	//rootCA, err := ca.NewCA(caDir)
	//assert.NoError(t, err, "Error generating CA")

	cert, err := rootCA.SignCertificate(certDir, testName, nil, nil, priv,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageAny})
	assert.NoError(t, err, "Failed to generate signed certificate")
	// KeyUsage should be x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	assert.Equal(t, sm2.KeyUsageDigitalSignature|sm2.KeyUsageKeyEncipherment,
		cert.KeyUsage)
	assert.Contains(t, cert.ExtKeyUsage, sm2.ExtKeyUsageAny)
}

func cleanup(dir string) {
	os.RemoveAll(dir)
}

func checkForFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}

func TestHash(t *testing.T) {
	hash := sm2.SM3.New()
	hash.Write([]byte("123"))
	digest := hash.Sum(nil)
	fmt.Println(base64.StdEncoding.EncodeToString(digest))

	ns := netsign.NetSign{Ip: "39.100.115.152"}
	bytes, _ := ns.Hash(35000, "sm3", []byte("123"))
	fmt.Println(string(bytes))

}

type sm2Signature struct {
	R, S *big.Int
}

//func TestSign(t *testing.T) {
//	privateKey := "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg7JYqXV1kVCZ+x9mn5X5+Yj+cULF3325WGIaNkY/V0lqgCgYIKoEcz1UBgi2hRANCAAR1t1Y8cj0LEJANrIXKh3qd+Ntxbwp9EhyfJzTILIDi/9yy96YVbfDhWfMoQjIOlU6Kq9uFQ/qPM2Q0sKsHMWb6"
//	//publicKey:="MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEdbdWPHI9CxCQDayFyod6nfjbcW8KfRIcnyc0yCyA4v/csvemFW3w4VnzKEIyDpVOiqvbhUP6jzNkNLCrBzFm+g=="
//
//	//prider, _ := pem.Decode([]byte(privateKey))
//	//priv, err := sm2.ParsePKCS8UnecryptedPrivateKey(prider.Bytes)
//	decodeString, err := base64.StdEncoding.DecodeString(privateKey)
//	priv, err := sm2.ParsePKCS8UnecryptedPrivateKey(decodeString)
//
//	hash := sm2.SM3.New()
//	fmt.Println([]byte("Hello World"))
//	hash.Write([]byte{72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100})
//	digest := hash.Sum(nil)
//	r, s, err := sm2.Sign(priv, digest)
//	if err != nil {
//		fmt.Println(err)
//	}
//	marshal, err := asn1.Marshal(sm2Signature{r, s})
//
//	fmt.Println(base64.StdEncoding.EncodeToString(marshal))
//}
//func /**/TestVerify(t *testing.T) {
//
//	ns := netsign.NetSign{}
//	p10, _ := ns.GenP10(1, "CN=China", "test", "sm2")
//	p10Bytes, _ := base64.StdEncoding.DecodeString(string(p10))
//	request, _ := sm2.ParseCertificateRequest(p10Bytes)
//	publicKey := request.PublicKey.(*sm2.PublicKey)
//	ns.UploadCert(1, "test", []byte("hello"))
//
//	signature, _ := ns.Sign(1, 1, []byte("hello world"), "test", "sm3")
//	fmt.Println(ns.Verify(1, 1, []byte("hello world"), signature, "test", "sm3"))
//	var sig sm2Signature
//	asn1.Unmarshal(signature, &sig)
//
//	//hash := sm2.SM3.New()
//	//hash.Write([]byte("hello world"))
//	//digest := hash.Sum(nil)
//
//	verify := sm2.Verify(publicKey, []byte("hello world"), sig.R, sig.S)
//	fmt.Println(verify)
//
//}
func Test_sign_verify(t *testing.T) {
	ip := os.Getenv("CORE_PEER_BCCSP_CNCC_GM_IP")
	portString := os.Getenv("CORE_PEER_BCCSP_CNCC_GM_PORT")
	port, _ := strconv.Atoi(portString)
	password := os.Getenv("CORE_PEER_BCCSP_CNCC_GM_PASSWORD")
	//keyLabel := flag.Args()[0]
	keyLabel := "Baas194862282219757084353127923110381254468"

	netsign := netsign.NetSign{}
	socketFd, ret := netsign.OpenNetSign(ip, password, port)
	if ret != 0 {
		panic("open netsign error")
	}
	sig, ret := netsign.Sign(socketFd, 0, []byte("hello world"), keyLabel, "SM3")
	if ret != 0 {
		panic("sign error")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
	ret = netsign.Verify(socketFd, 1, []byte("hello world"), sig, keyLabel, "SM3")
	fmt.Println(ret)
}
func Test_sign_verify1(t *testing.T) {
	ip := "111.63.61.22"
	portString := "50060"
	port, _ := strconv.Atoi(portString)
	password := "a"
	ip1 := "111.63.61.21"
	portString1 := "50060"
	port1, _ := strconv.Atoi(portString1)
	keyLabel := "Baas299930322631645987651414658902474957388"

	netsign := netsign.NetSign{}
	socketFd, ret := netsign.OpenNetSign(ip, password, port)
	if ret != 0 {
		fmt.Println(ret)
		panic("open netsign error")
	}
	sig, ret := netsign.Sign(socketFd, 0, []byte("hello world"), keyLabel, "SM3")
	if ret != 0 {
		fmt.Println(ret)
		panic("sign error")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
	ret = netsign.Verify(socketFd, 1, []byte("hello world"), sig, keyLabel, "SM3")
	fmt.Println(ret)

	socketFd1, ret := netsign.OpenNetSign(ip1, password, port1)
	if ret != 0 {
		fmt.Println(ret)
		panic("open netsign error")
	}
	sig1, ret := netsign.Sign(socketFd1, 0, []byte("hello world"), keyLabel, "SM3")
	if ret != 0 {
		fmt.Println(ret)
		panic("sign error")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(sig1))
	ret = netsign.Verify(socketFd1, 1, []byte("hello world"), sig1, keyLabel, "SM3")
	fmt.Println(ret)

}
func Test_GenP10(t *testing.T) {
	ip := "111.1.30.17"
	portString := "50060"
	port, _ := strconv.Atoi(portString)
	password := "a"
	ip1 := "111.1.30.17"
	portString1 := "50070"
	port1, _ := strconv.Atoi(portString1)

	netsign := netsign.NetSign{}
	socketFd, ret := netsign.OpenNetSign(ip, password, port)
	if ret != 0 {
		panic("open netsign error")
	}
	id := RandStringInt()
	p10, ret := netsign.GenP10(socketFd, "test", "test"+id, "SM2")

	if ret != 0 {
		panic("sign error")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(p10))

	socketFd, ret = netsign.OpenNetSign(ip1, password, port1)
	if ret != 0 {
		panic("open netsign error")
	}
	id = RandStringInt()
	p10, ret = netsign.GenP10(socketFd, "test", "test"+id, "SM2")

	if ret != 0 {
		panic("sign error")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(p10))

}

// 产生随机数
func RandStringInt() string {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	return serialNumber.String()
}

func TestCreateCrl(t *testing.T) {
	cabytes, err := ioutil.ReadFile("/tmp/ca-test/ca/root1-cert.pem")
	caCert, err := sm2.ReadCertificateFromMem(cabytes)
	if err != nil {
		panic(err)
	}
	var certs []sm2.CertificateRecord
	var cert sm2.CertificateRecord
	signBytes, err := ioutil.ReadFile("/tmp/ca-test/certs/cert0-cert.pem")
	signCert, err := sm2.ReadCertificateFromMem(signBytes)
	if err != nil {
		panic(err)
	}
	cert.Serial = signCert.SerialNumber
	cert.Reason = 1
	cert.RevokedAt = time.Now()
	cert.Expiry = time.Now().Add(100 * 365 * 24 * time.Hour)
	certs = append(certs, cert)

	opts := &factory.FactoryOpts{
		ProviderName: "CNCC_GM",
		CNCC_GMOpts: &cncc.CNCC_GMOpts{
			HashFamily: "GMSM3",
			SecLevel:   256,
		},
	}

	// 从 ca 中获取签名实例
	csp, err := factory.GetBCCSPFromOpts(opts)
	var s crypto.Signer
	if err == nil {
		// generate a key
		priv, err := csp.GetKey(caCert.SubjectKeyId)
		if err == nil {
			// create a crypto.Signer
			s, err = signer.New(csp, priv)
		}
	}

	// 获取 crl 文件的过期时间
	// expiry := time.Now().UTC().Add(ca.Config.CRL.Expiry)
	expiry := time.Now().UTC().Add(100 * 365 * 24 * time.Hour)

	var revokedCerts []pkix.RevokedCertificate

	// For every record, create a new revokedCertificate and add it to slice
	for _, certRecord := range certs {
		//serialInt := new(big.Int)
		//serialInt.SetString(certRecord.Serial, 16)
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   certRecord.Serial,
			RevocationTime: certRecord.RevokedAt,
		}
		revokedCerts = append(revokedCerts, revokedCert)
	}

	crlBytes, err := caCert.CreateCRL(rand.Reader, s, revokedCerts, time.Now(), expiry)
	fmt.Println(base64.StdEncoding.EncodeToString(crlBytes))

	ioutil.WriteFile("/root/ca.crl", crlBytes, os.FileMode(0666))
}

func Test_der2pem(t *testing.T) {
	//certBytes, _ := ioutil.ReadFile("/opt/go/src/github.com/hyperledger/fabric-samples/first-network/crypto-config" +
	//	"/ordererOrganizations/example.com/ca/ca.example.com-cert.pem")
	//block, _ := pem.Decode(certBytes)
	//
	//ioutil.WriteFile("/opt/go/src/github.com/hyperledger/fabric-samples/first-network/crypto-config"+
	//	"/ordererOrganizations/example.com/ca/ca.example.com-cert.cer-1", block.Bytes, os.FileMode(0666))
	certBytes, _ := ioutil.ReadFile("/root/qwer0311005/NPC-ca.cer")
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	pembytes := pem.EncodeToMemory(block)

	ioutil.WriteFile("/root/ca.pem", pembytes, os.FileMode(0666))
}
func Test_pem2der(t *testing.T) {
	//certBytes, _ := ioutil.ReadFile("/opt/go/src/github.com/hyperledger/fabric-samples/first-network/crypto-config" +
	//	"/ordererOrganizations/example.com/ca/ca.example.com-cert.pem")
	//block, _ := pem.Decode(certBytes)
	//
	//ioutil.WriteFile("/opt/go/src/github.com/hyperledger/fabric-samples/first-network/crypto-config"+
	//	"/ordererOrganizations/example.com/ca/ca.example.com-cert.cer-1", block.Bytes, os.FileMode(0666))
	certBytes, _ := ioutil.ReadFile("/root/桌面/ca.pem")
	block, _ := pem.Decode(certBytes)

	ioutil.WriteFile("/root/桌面/ca.cer", block.Bytes, os.FileMode(0666))
}

func Test_parseSM2cert(t *testing.T) {

	//certBytes, _ := ioutil.ReadFile("/tmp/ca-test/ca/root0-cert.pem")
	//
	//caCert, err := sm2.ReadCertificateFromMem(certBytes)
	//fmt.Println(caCert.SerialNumber)
	//fmt.Println(string(caCert.SubjectKeyId))
	//fmt.Println("199659743608592606807626285519651546178")
	//
	//if err != nil {
	//	fmt.Println(err.Error())
	//}
	//fmt.Println(caCert)
	//
	//userBytes, _ := ioutil.ReadFile("/root/桌面/user.pem")
	//
	//userCert, err := sm2.ReadCertificateFromMem(userBytes)
	//fmt.Println("signature:", hex.EncodeToString(userCert.Signature))
	//za, err := sm2.ZA(caCert.PublicKey.(*sm2.PublicKey), userCert.RawTBSCertificate)
	//fmt.Println("za:", hex.EncodeToString(za))
	//if err != nil {
	//	fmt.Println(err.Error())
	//}
	//fmt.Println(userCert)
	//
	//adminBytes, _ := ioutil.ReadFile("/root/桌面/Admin@example.com-cert.pem")
	//
	//
	//mem, err = sm2.ReadCertificateFromMem(adminBytes)
	//fmt.Println("signature:",hex.EncodeToString(mem.Signature))
	//if err!=nil{
	//	fmt.Println(err.Error())
	//}
	//fmt.Println(mem)
	creatorBytes, _ := ioutil.ReadFile("/opt/go/src/github.com/hyperledger/tlsuser")
	//certStart := strings.Index(string(creatorBytes), "-----BEGIN")
	//fmt.Println(index)
	certStart := bytes.Index(creatorBytes, []byte("-----BEGIN"))
	certText := creatorBytes[certStart:]
	bl, _ := pem.Decode(certText)
	cert, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		fmt.Println("ParseCertificate failed")
	}
	fmt.Println(string(cert.SubjectKeyId))
}

type NetSignConfig struct {
	Ip     string
	Port   string
	Passwd string
}

func Test_test(t *testing.T) {

	NetSignConfigMap := make(map[string]map[int]NetSignConfig, 2)

	NetSignConfigMap["BJ"] = make(map[int]NetSignConfig, 2)

	NetSignConfigMap["BJ"][0] = NetSignConfig{"123456", "50060", "111.63.61.22"}
	NetSignConfigMap["BJ"][1] = NetSignConfig{"123456", "50061", "111.63.61.23"}

	NetSignConfigMap["SH"] = make(map[int]NetSignConfig, 2)

	NetSignConfigMap["SH"][0] = NetSignConfig{"123456", "50060", "17.63.61.22"}
	NetSignConfigMap["SH"][1] = NetSignConfig{"123456", "50061", "17.63.61.23"}

	ip := os.Getenv("CORE_PEER_BCCSP_CNCC_GM_IP")
	portString := os.Getenv("CORE_PEER_BCCSP_CNCC_GM_PORT")
	password := os.Getenv("CORE_PEER_BCCSP_CNCC_GM_PASSWORD")

	fmt.Println(ip, password, portString)
}

func parseString(ip, port, passwd string) {

	ip = strings.Trim(ip, ",;")
	port = strings.Trim(port, ",;")
	passwd = strings.Trim(passwd, ",;")

	var BJ_NetSignConfig []*NetSignConfig
	var SH_NetSignConfig []*NetSignConfig

	split1 := strings.Split(ip, ";")
	split2 := strings.Split(port, ";")
	split3 := strings.Split(passwd, ";")

	if len(split1) != len(split2) || len(split1) != len(split3) || len(split2) != len(split3) {
		panic("netsign config error")
	}

	if len(split1) == 1 {
		BJ_NetSignConfig = parseNetsigns(split1[0], split2[0], split3[0])
	} else if len(split1) == 2 {
		BJ_NetSignConfig = parseNetsigns(split1[0], split2[0], split3[0])
		SH_NetSignConfig = parseNetsigns(split1[1], split2[1], split3[1])
	} else {
		panic("netsign config error")
	}
	fmt.Println(BJ_NetSignConfig)
	fmt.Println(SH_NetSignConfig)
}

func parseNetsigns(ip, port, passwd string) []*NetSignConfig {
	var signs []*NetSignConfig

	ips := strings.Split(ip, ",")
	ports := strings.Split(port, ",")
	passwds := strings.Split(passwd, ",")
	if len(ips) != len(ports) || len(ips) != len(passwds) || len(ports) != len(passwds) {
		panic("netsign config error")
	}
	for i, ip := range ips {
		net := &NetSignConfig{
			Ip:     ip,
			Port:   ports[i],
			Passwd: passwds[i],
		}
		signs = append(signs, net)
	}
	return signs
}

func Test_telnet(t *testing.T) {
	address := net.JoinHostPort("47.105.180.88", "19443")
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err == nil {
		if conn != nil {
			fmt.Println("success")
			_ = conn.Close()
		}

	} else {
		fmt.Println(err.Error())
	}
}
func Test_CNCC_NETSIGN(t *testing.T) {
	ns1 := NetSignConfig{
		Ip:     "47.105.180.88",
		Port:   "19443",
		Passwd: "123456",
	}
	ns2 := NetSignConfig{
		Ip:     "47.105.180.88",
		Port:   "19444",
		Passwd: "123456",
	}
	ns3 := NetSignConfig{
		Ip:     "47.105.180.88",
		Port:   "19445",
		Passwd: "123456",
	}
	ns4 := NetSignConfig{
		Ip:     "47.105.180.88",
		Port:   "19446",
		Passwd: "123456",
	}

	var BJ_NetSignConfig []*NetSignConfig
	var SH_NetSignConfig []*NetSignConfig
	var BAK_NetSignConfig []*NetSignConfig

	BJ_NetSignConfig = append(BJ_NetSignConfig, &ns1)
	BJ_NetSignConfig = append(BJ_NetSignConfig, &ns2)
	SH_NetSignConfig = append(SH_NetSignConfig, &ns3)
	SH_NetSignConfig = append(SH_NetSignConfig, &ns4)

	BAK_NetSignConfig = BJ_NetSignConfig
	BJ_NetSignConfig = SH_NetSignConfig
	SH_NetSignConfig = BAK_NetSignConfig

	fmt.Println(len(BJ_NetSignConfig))
	fmt.Println(len(SH_NetSignConfig))
	fmt.Println(BAK_NetSignConfig[0].Port)
	fmt.Println(SH_NetSignConfig[0].Port)
	fmt.Println(BJ_NetSignConfig[0].Port)

	BAK_NetSignConfig = nil
	fmt.Println(len(BAK_NetSignConfig))

	BAK_NetSignConfig = SH_NetSignConfig
	fmt.Println(BAK_NetSignConfig[0].Port)
}

func Test_goroutine(t *testing.T) {
	//ns1:=cncc.NetSignConfig{
	//	Ip:"47.105.180.88",
	//	Port:"35000",
	//	Passwd:"123456",
	//}
	//ns2:=cncc.NetSignConfig{
	//	Ip:"47.105.180.88",
	//	Port:"34999",
	//	Passwd:"123456",
	//}
	//ns3:=cncc.NetSignConfig{
	//	Ip:"47.105.180.88",
	//	Port:"34998",
	//	Passwd:"123456",
	//}
	//ns4:=cncc.NetSignConfig{
	//	Ip:"47.105.180.88",
	//	Port:"34997",
	//	Passwd:"123456",
	//}
	//
	//cncc.BJ_NetSignConfig = append(cncc.BJ_NetSignConfig,&ns1)
	//cncc.BJ_NetSignConfig = append(cncc.BJ_NetSignConfig,&ns2)
	//cncc.BJ_NetSignConfig = append(cncc.BJ_NetSignConfig,&ns2)
	//cncc.SH_NetSignConfig = append(cncc.SH_NetSignConfig,&ns3)
	//cncc.SH_NetSignConfig = append(cncc.SH_NetSignConfig,&ns4)
	factory.InitFactories(nil)
	//go factory.TimeTick()

	for {
		time.Sleep(time.Second)
		for _, v := range cncc.BJ_NetSignConfig {

			fmt.Println("beijing", v.Port)
		}
		for _, v := range cncc.SH_NetSignConfig {

			fmt.Println("shanghai", v.Port)
		}

	}
}
func Test_equal(t *testing.T) {

	str1 := "beijing"
	str2 := "BEIJING"
	if strings.EqualFold(str1, str2) {
		fmt.Println("success")
	}

	sessions := make(chan *cncc.NetSignSesssion, 2)
	fmt.Println(len(sessions))
	fmt.Println(cap(sessions))
}
func TestNetSign(t *testing.T) {
	ns := netsign.NetSign{Ip: "47.95.204.66"}
	socketFd := 34998

	sign, ret := ns.Sign(socketFd, 0, []byte("MQ=="), "string", "sm3")
	if ret != 0 {
		fmt.Println("sign error")
	}

	fmt.Println(string(sign))
}
func TestNetSign_CloseNetSign(t *testing.T) {
	ns := netsign.NetSign{}
	socketFd, ret := ns.OpenNetSign("47.95.204.66", "CNCC123456", 34997)
	if ret != 0 {
		fmt.Println("open netsign error")
	}
	p10, ret := ns.GenP10(socketFd, "CN=brilliance", "test", "SM2")
	if ret != 0 {
		fmt.Println("generate p10 error")
	}
	
	ret = ns.UploadCert(socketFd, "test", p10)
	if ret != 0 {
		fmt.Println("upload cert error")
	}
	sign, ret := ns.Sign(socketFd, 0, []byte("hello world"), "test", "sm3")
	if ret != 0 {
		fmt.Println("sign error")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(sign))
	ret = ns.Verify(socketFd, 1, []byte("hello world"), sign, "test", "sm3")
	if ret != 0 {
		fmt.Println("verify error")
	}
	
}
func TestTimeTick(t *testing.T) {
	channelTest := make(chan int, 5)
	go test1(channelTest)
	for range time.Tick(5 * time.Second) {
		for i := 0; i < 5; i++ {
			fmt.Printf("in:")
			fmt.Println(i)
			channelTest <- i
		}

	}
}
func test1(channel chan int) {
	fmt.Printf("out:")
	for {
		fmt.Println(<-channel)
	}
}
func TestSetTimeOut(t *testing.T) {
	ns := netsign.NetSign{Ip: "111.63.61.22"}
	ns.SetTimeOutMsec(3000)
	port := 50064
	socketFd, ret := ns.OpenNetSign(ns.Ip, "12", port)
	port = 50063
	socketFd1, ret := ns.OpenNetSign(ns.Ip, "12", port)
	if ret == 0 {
		fmt.Println("open netsign success")
	}
	time.Sleep(10 * time.Second)
	fmt.Println(time.Now())
	sign, ret := ns.Sign(socketFd, 0, []byte("MQ=="), "SM2SignKey48223349433801239646462631783924258765", "sm3")
	if ret != 0 {
		fmt.Printf("sign error, ret=%d", ret)
	}
	fmt.Println(string(sign))
	fmt.Println(time.Now())

	ns = netsign.NetSign{Ip: "111.63.61.22"}

	fmt.Println(time.Now())
	sign, ret = ns.Sign(socketFd1, 0, []byte("MQ=="), "SM2SignKey48223349433801239646462631783924258765", "sm3")
	if ret != 0 {
		fmt.Printf("sign error, ret=%d", ret)
	}
	fmt.Println(string(sign))
	fmt.Println(time.Now())
}
type QueryBaseInfo struct {
	Url    string   				`json:"url,omitempty"`      // 请求的url
	Method string   				`json:"method,omitempty"`   // 请求的方法
	Params map[string]interface{} 	`json:"params,omitempty"`   // 请求的数据
}

func TestQueryBaseInfo(t *testing.T)  {
	queryBaseInfo:=QueryBaseInfo{Url:"https://orderer.example.com:9443/test/genP10/SM2?certDN=CN=CNCC",
		Method:"",
		Params: map[string]interface{}{
			"cover":true,
			"port":34997,
	}}
	marshal, _ := json.Marshal(queryBaseInfo)
	fmt.Println(string(marshal[:]))
}
