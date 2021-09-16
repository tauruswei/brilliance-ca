package cert_service

import (
	"crypto"
	"crypto/x509"
	"github.com/brilliance/ca/common/config"
	"github.com/brilliance/ca/common/global"
	logger "github.com/brilliance/ca/common/log"
	"github.com/brilliance/ca/common/util"
	"github.com/brilliance/ca/dao"
	"github.com/brilliance/ca/model"
	"github.com/pkg/errors"
	"strings"
	"time"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/9/8 下午5:20
 */
func NewCA(request model.NewCARequest) (*dao.Cert, error) {
	tx := global.SQLDB.Begin()
	// 生成私钥在本地的临时目录
	//keyStore:=util.MakeTempdir()
	//defer os.RemoveAll(keyStore)

	// 获取签发者证书
	var caSigner crypto.Signer
	subject := &(dao.Subject{CertificateSubject: request.IssuerSubject})
	cert := &(dao.Cert{})
	certificateSubject, err := subject.GetByCertificateSubject(tx)
	if (err != nil) && (!(strings.Contains(err.Error(), "record not found"))) {
		logger.Error(util.GetErrorStackf(err, "获取 issuer 证书主题失败：request = %+v", request))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "获取 issuer 证书主题失败：request = %+v", request)
	} else if err == nil {
		cert.IssuerId = certificateSubject.Id
		caCert := &(dao.Cert{})
		caCert, err = (&dao.Cert{SubjectId: certificateSubject.Id}).GetBySubjectId(tx)
		if err != nil {
			logger.Error(util.GetErrorStackf(err, "获取 issuer 证书失败：request = %+v", request))
			tx.Rollback()
			return nil, errors.WithMessagef(err, "获取 issuer 证书失败：request = %+v", request)
		}

		_, caSigner, err = util.ImportPrivateKey(caCert.KeySize, caCert.PrivateKey, caCert.Provider, caCert.CryptoType,
			config.KeyStore)
		if err != nil {
			logger.Error(util.GetErrorStackf(err, "获取 issuer signer 失败：caCert = %+v", caCert))
			tx.Rollback()
			return nil, errors.WithMessagef(err, "获取 issuer signer 失败：caCert = %+v", caCert)
		}
		if !strings.EqualFold(request.CryptoType, caCert.CryptoType) {
			logger.Error(util.GetErrorStackf(err, "crypto type 不一致：caCert ctyptoType = %s, request cryptoType = %s",
				caCert.CryptoType, request.CryptoType))
			tx.Rollback()
			return nil, errors.WithMessagef(err, "crypto type 不一致：caCert ctyptoType = %s, request cryptoType = %s",
				caCert.CryptoType, request.CryptoType)
		}
	}

	// 生成私钥
	priv, _, err := util.GenPrivateKey(request.KeySize, request.Provider, request.CryptoType, config.KeyStore)
	if err != nil {
		logger.Error(util.GetErrorStack(err, ""))
		tx.Rollback()
		return nil, err
	}

	// 签发证书
	cerSubject := util.SubjectTemplateAdditional(request.CommonName, request.Org, request.Country, request.Province, request.Locality, request.OrgUnit,
		request.StreetAddress, request.PostalCode)
	certificate, err := util.GenCertificate(request.CertificateRequest, priv, caSigner, cerSubject,
		x509.KeyUsageDigitalSignature|
			x509.KeyUsageKeyEncipherment|x509.KeyUsageCertSign|
			x509.KeyUsageCRLSign, []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}, request.CryptoType)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "生成证书失败"))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "生成证书失败")
	}
	subject.CertificateSubject = cerSubject.String()
	subject.CreateTime = time.Now().Format("2006-01-02 15:04:05")
	subject.UpdateTime = time.Now().Format("2006-01-02 15:04:05")
	err = subject.Create(tx)

	if err != nil {
		logger.Error(util.GetErrorStackf(err, "subject 存库失败: subject = %+v", subject))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "subject 存库失败: subject = %+v", subject)
	}

	util.CopyFields(cert, request)
	cert.Certificate = string(certificate)
	cert.CertificateStatus = 1
	cert.SubjectId = subject.Id
	privpem, err := util.LoadPrivateKey(config.KeyStore)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "读取密钥失败: keyStore = %s", config.KeyStore))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "读取密钥失败: keyStore = %s", config.KeyStore)
	}
	cert.PrivateKey = privpem
	cert.StartDate = time.Now().Format("2006-01-02 15:04:05")
	cert.Expiration = time.Now().Add(time.Duration(request.Period) * time.Hour).Format("2006-01-02 15:04:05")
	cert.CreateTime = time.Now().Format("2006-01-02 15:04:05")
	cert.UpdateTime = time.Now().Format("2006-01-02 15:04:05")
	err = cert.Create(tx)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "证书保存数据库失败: cert = %+v", cert))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "证书保存数据库失败: cert = %+v", cert)
	}
	tx.Commit()
	return cert, nil
}

func SignCert(request model.SignCertRequest) (*dao.Cert, error) {
	tx := global.SQLDB.Begin()

	key, err := (&dao.Key{Name: request.KeyName}).GetByKeyName(global.SQLDB)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "获取 key 失败: request = %+v", request))
		return nil, errors.WithMessagef(err, "获取 key 失败: request = %+v", request)
	}

	// 获取签发者证书
	var signer crypto.Signer
	subject := &(dao.Subject{CertificateSubject: request.IssuerSubject})
	cert := &(dao.Cert{})
	certificateSubject, err := subject.GetByCertificateSubject(tx)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "获取 issuer 证书主题失败：request = %+v", request))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "获取 issuer 证书主题失败：request = %+v", request)
	}
	cert.IssuerId = certificateSubject.Id
	caCert := &(dao.Cert{})
	caCert, err = (&dao.Cert{SubjectId: certificateSubject.Id}).GetBySubjectId(tx)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "获取 issuer 证书失败：request = %+v", request))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "获取 issuer 证书失败：request = %+v", request)
	}

	_, signer, err = util.ImportPrivateKey(caCert.KeySize, caCert.PrivateKey, caCert.Provider, caCert.CryptoType, "")
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "获取 issuer signer 失败：caCert = %+v", caCert))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "获取 issuer signer 失败：caCert = %+v", caCert)
	}
	if !strings.EqualFold(caCert.CryptoType, key.CryptoType) {
		logger.Error(util.GetErrorStackf(err, "crypto type 不一致：caCert ctyptoType = %s, key cryptoType = %s", caCert.CryptoType, key.CryptoType))
		tx.Rollback()
		return nil, errors.Errorf("crypto type 不一致：caCert ctyptoType = %s, key cryptoType = %s", caCert.CryptoType, key.CryptoType)
	}
	if !strings.EqualFold(caCert.Provider, key.Provider) {
		logger.Error(util.GetErrorStackf(err, "crypto provider 不一致：caCert provider = %s, key provider = %s", caCert.Provider, key.Provider))
		tx.Rollback()
		return nil, errors.Errorf("crypto provider 不一致：caCert provider = %s, key provider = %s", caCert.Provider, key.Provider)
	}

	// 获取签名证书的私钥
	priv, _, err := util.ImportPrivateKey(0, key.PrivateKey, caCert.Provider, caCert.CryptoType, "")
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "获取 private key 失败: keyName = %s", request.KeyName))
		return nil, errors.WithMessagef(err, "获取 private key 失败:  keyName = %s", request.KeyName)
	}

	// 签发证书
	cerSubject := util.SubjectTemplateAdditional(request.CommonName, request.Org, request.Country,
		request.Province,
		request.Locality, request.OrgUnit,
		request.StreetAddress, request.PostalCode)
	certificate, err := util.GenCertificate(request.CertificateRequest, priv, signer, cerSubject, x509.KeyUsageDigitalSignature,
		[]x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}, caCert.CryptoType)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "生成证书失败"))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "生成证书失败")
	}
	subject.CertificateSubject = cerSubject.String()
	subject.CreateTime = time.Now().Format("2006-01-02 15:04:05")
	subject.UpdateTime = time.Now().Format("2006-01-02 15:04:05")
	err = subject.Create(tx)

	if err != nil {
		logger.Error(util.GetErrorStackf(err, "subject 存库失败: subject = %+v", subject))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "subject 存库失败: subject = %+v", subject)
	}

	util.CopyFields(cert, request)
	cert.Certificate = string(certificate)
	cert.CertificateStatus = 1
	cert.SubjectId = subject.Id
	cert.CryptoType = key.CryptoType
	cert.KeySize = key.KeySize
	cert.Provider = key.Provider
	cert.PrivateKey = key.PrivateKey
	cert.StartDate = time.Now().Format("2006-01-02 15:04:05")
	cert.Expiration = time.Now().Add(time.Duration(request.Period) * time.Hour).Format(
		"2006-01-02 15:04:05")
	cert.CreateTime = time.Now().Format("2006-01-02 15:04:05")
	cert.UpdateTime = time.Now().Format("2006-01-02 15:04:05")
	err = cert.Create(tx)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "证书保存数据库失败: cert = %+v", cert))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "证书保存数据库失败: cert = %+v", cert)
	}
	tx.Commit()
	return cert, nil
}
func RevokeCert(request model.RevokeRequest) error {
	tx := global.SQLDB.Begin()
	subject, err := (&dao.Subject{CertificateSubject: request.CertificateSubject}).GetByCertificateSubject(tx)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "获取证书主题失败：certificateSubject = %s", request.CertificateSubject))
		tx.Rollback()
		return errors.WithMessagef(err, "获取证书主题失败：certificateSubject = %s", request.CertificateSubject)
	}

	cert, err := (&dao.Cert{SubjectId: subject.Id}).GetBySubjectId(tx)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "获取证书失败：certificateSubject = %s", request.CertificateSubject))
		tx.Rollback()
		return errors.WithMessagef(err, "获取证书失败：certificateSubject = %s", request.CertificateSubject)
	}
	cert.CertificateStatus = 2
	cert.UpdateTime = time.Now().Format("2006-01-02 15:04:05")
	err = cert.UpdateCertStatus(tx)
	if err != nil {
		logger.Error(util.GetErrorStackf(err, "更新证书状态失败：cert = %+v", cert))
		tx.Rollback()
		return errors.WithMessagef(err, "更新证书状态失败：cert = %+v", cert)
	}
	tx.Commit()
	return nil
}

//func GenCSR(request model.CertificateSigningRequest) (interface{}, error) {
//	cerSubject := subjectTemplateAdditional(request.CommonName, request.Org, request.Country, request.Province, request.Locality, request.OrgUnit,
//		request.StreetAddress, request.PostalCode)
//	var cr = &model.CertificateRequest{}
//	CopyFields(cr, request)
//
//	key, err := (&dao.Key{Name: request.KeyName}).GetByKeyName(global.SQLDB)
//	if err != nil {
//		logger.Error(util.GetErrorStackf(err, "获取 key 失败: %s", request.KeyName))
//		return nil, errors.WithMessagef(err, "获取 key 失败: %s", request.KeyName)
//	}
//
//	pubkey, err := ImportPublicKey(0, key.PrivateKey, request.Provider, request.CryptoType, "")
//
//	if err != nil {
//		logger.Error(util.GetErrorStack(err, "获取 public key 失败"))
//		return nil, errors.WithMessage(err, "获取 public key 失败")
//	}
//	return GenCertificateSignRequest(cr, pubkey, cerSubject, x509.KeyUsageDigitalSignature,[]x509.ExtKeyUsage{
//		x509.ExtKeyUsageClientAuth,
//		x509.ExtKeyUsageServerAuth,
//	})
//}
