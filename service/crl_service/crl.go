package crl_service

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/brilliance/ca/backend/dao"
	"github.com/brilliance/ca/common/global"
	logger "github.com/brilliance/ca/common/log"
	"github.com/brilliance/ca/common/util"
	"github.com/brilliance/ca/model"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"os"
	"strings"
	"time"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/9/10 下午3:50
 */

func GenCrl(request model.CrlRequest) (*dao.Crl, error) {
	tx := global.SQLDB.Begin()

	// 生成私钥的临时目录
	keyStore := util.MakeTempdir()
	defer os.RemoveAll(keyStore)

	// 获取 issuer 证书主题
	cert := &dao.Cert{}
	var certs []*dao.Cert
	var caCert *dao.Cert
	certificateSubject, err := (&dao.Subject{CertificateSubject: request.IssuerSubject}).GetByCertificateSubject(tx)
	if (err != nil) && (!(strings.Contains(err.Error(), "record not found"))) {
		logger.Errorf(util.GetErrorStackf(err, "获取 issuer 证书主题失败：request = %v", request))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "获取 issuer 证书主题失败：request = %v", request)
	} else if err == nil {
		cert.IssuerId = certificateSubject.Id
		cert.CertificateStatus = 2
		certs, err = cert.GetByIssuerIdAndStatus(tx)

		if err != nil {
			logger.Errorf(util.GetErrorStackf(err, "获取 revoked certs 失败：request = %v", request))
			tx.Rollback()
			return nil, errors.WithMessagef(err, "获取 revoked certs 失败：request = %v", request)
		}
		cert.SubjectId = certificateSubject.Id
		caCert, err = cert.GetBySubjectId(tx)
		if err != nil {
			logger.Errorf(util.GetErrorStackf(err, "获取 issuer 证书失败：request = %v", request))
			tx.Rollback()
			return nil, errors.WithMessagef(err, "获取 issuer 证书失败：request = %v", request)
		}
	}

	_, signer, err := util.ImportPrivateKey(caCert.KeySize, caCert.PrivateKey, caCert.Provider,
		caCert.CryptoType, "")
	expiry := time.Now().UTC().Add(100 * 365 * 24 * time.Hour)
	caCertificate, err := sm2.ReadCertificateFromMem([]byte(caCert.Certificate))

	var certificates []sm2.CertificateRecord
	var certificate sm2.CertificateRecord
	for _, certi := range certs {
		signCert, err := sm2.ReadCertificateFromMem([]byte(certi.Certificate))
		if err != nil {

			logger.Error(util.GetErrorStackf(err, "解析证书失败：certificate = %s", certi))
			tx.Rollback()
			return nil, errors.WithMessagef(err, "解析证书失败：certificate = %s", certi)
		}
		certificate.Serial = signCert.SerialNumber
		certificate.Reason = 1
		certificate.RevokedAt = time.Now()
		certificate.Expiry = time.Now().Add(100 * 365 * 24 * time.Hour)
		certificates = append(certificates, certificate)
	}

	var revokedCerts []pkix.RevokedCertificate

	// For every record, create a new revokedCertificate and add it to slice
	for _, certRecord := range certificates {
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   certRecord.Serial,
			RevocationTime: certRecord.RevokedAt,
		}
		revokedCerts = append(revokedCerts, revokedCert)
	}
	crlBytes, err := caCertificate.CreateCRL(rand.Reader, signer, revokedCerts, time.Now(), expiry)

	//fmt.Println(base64.StdEncoding.EncodeToString(crlBytes))

	if err != nil {
		logger.Error(util.GetErrorStack(err, "生成crl文件失败"))
		tx.Rollback()
		return nil, errors.WithMessagef(err, "生成crl文件失败")
	}

	blk := &pem.Block{Bytes: crlBytes, Type: "X509 CRL"}

	crlPem := pem.EncodeToMemory(blk)

	crl := &dao.Crl{}
	crl.IssuerId = caCert.SubjectId
	splits := strings.Split(request.IssuerSubject, ",")
	for _, str := range splits {
		if strings.Contains(str, "CN=") {
			crl.Name = fmt.Sprintf("%s-CRL", strings.Split(str, "=")[1])
		}
	}

	crl.Crl = string(crlPem)
	crl.CreateTime = time.Now().Format("2006-01-02 15:04:05")
	crl.UpdateTime = time.Now().Format("2006-01-02 15:04:05")

	crl1, err := (&dao.Crl{IssuerId: caCert.SubjectId}).GetByIssueId(tx)
	if crl1 == nil {
		err = crl.Create(tx)
	} else {
		err = (&dao.Crl{Id: crl1.Id, Crl: string(crlPem), UpdateTime: time.Now().Format("2006-01-02 15:04:05")}).UpdateCrl(tx)
	}
	if err != nil {
		logger.Error(util.GetErrorStack(err, "crl文件保存到数据库失败"))
		tx.Rollback()
		return nil, errors.WithMessage(err, "crl文件保存到数据库失败")
	}
	tx.Commit()
	return crl, nil

}
