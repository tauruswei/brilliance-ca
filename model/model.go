package model

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/6/10 下午3:46
 */
/*
	业务请求结构体
*/
type Envelope struct {
	Data        []byte `json:"data"`        // 业务合约请求数据, 对应 QueryBaseInfo
	Sig         []byte `json:"sig"`         // 签名值
	Certificate []byte `json:"certificate"` // 证书
}

/*
  业务合约请求数据  结构体
*/
type QueryBaseInfo struct {
	ContractName string                 `json:contractName,omitempty"` // 应用合约名字
	Method       string                 `json:"method,omitempty"`      // 请求的方法
	Params       map[string]interface{} `json:"params,omitempty"`      // 请求的数据
	SourceUrl    string                 `json:sourceUrl,omitempty"`    // 数据源地址
}

func GetBody(body io.ReadCloser, v interface{}) error {
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, v)
}

type CertificateRequest struct {
	Org           string `json:"org"`
	OrgUnit       string `json:"orgUnit"`
	Country       string `json:"country"`
	CommonName    string `json:"commonName"`
	Province      string `json:"province"`
	Locality      string `json:"locality"`
	StreetAddress string `json:"streetAddress"`
	PostalCode    string `json:"postalCode"`
	CryptoType    string `json:"cryptoType"`
	IsCA          bool   `json:"isCA"`
	KeySize       int    `json:"keySize"`
	IssuerSubject string `json:"issuerSubject"`
	Period        int    `json:"period"`
	Provider      string `json:"provider"`
}
type CertificateSigningRequest struct {
	Org           string `json:"org"`
	OrgUnit       string `json:"orgUnit"`
	Country       string `json:"country"`
	CommonName    string `json:"commonName"`
	Province      string `json:"province"`
	Locality      string `json:"locality"`
	StreetAddress string `json:"streetAddress"`
	PostalCode    string `json:"postalCode"`
	CryptoType    string `json:"cryptoType"`
	IsCA          bool   `json:"isCA"`
	KeyName       string `json:"keyName"`
	Period        int    `json:"period"`
	Provider      string `json:"provider"`
}

type SignCertRequest struct {
	KeyName            string `json:"keyName"`
	CertificateRequest
}

type KeyRequest struct {
	CryptoType string `json:"cryptoType"`
	KeySize    int    `json:"keySize"`
	Provider   string `json:"provider"`
}
type RevokeRequest struct {
	CertificateSubject string `json:"certificateSubject"`
}
type CrlRequest struct {
	IssuerSubject string `json:"issuerSubject"`
}
