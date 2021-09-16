package v1

import (
	"github.com/brilliance/ca/Result"
	"github.com/brilliance/ca/common/util"
	"github.com/brilliance/ca/model"
	"github.com/brilliance/ca/service/cert_service"
	"github.com/gin-gonic/gin"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/9/8 下午5:19
 */

// @Tags CA
// @Summary 新建 CA
// @Description Create a new CA certificate
// @Param CertificateRequest body model.CertificateRequest true "证书请求信息"
// @Accept  json
// @Produce  json
// @Success 200 {object} Result.Result
// @Router /ca/newCa [post]
func NewCA(c *gin.Context) {
	g := Result.Gin{C: c}
	request := model.NewCARequest{}
	err := util.Validator(c, &request, g)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	ca, err := cert_service.NewCA(request)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	g.Success(ca)
}

// @Tags CA
// @Summary CA 签发证书
// @Description CA sign a new certificate
// @Param SignCertRequest body model.SignCertRequest true "证书请求信息"
// @Accept  json
// @Produce  json
// @Success 200 {object} Result.Result
// @Router /ca/signCert [post]
func SignCert(c *gin.Context) {
	g := Result.Gin{C: c}
	request := model.SignCertRequest{}
	err := util.Validator(c, &request, g)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	cert, err := cert_service.SignCert(request)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	g.Success(cert)
}

//func GenCSR(c *gin.Context){
//	g := Result.Gin{C: c}
//	request := model.CertificateSigningRequest{}
//	err := model.GetBody(c.Request.Body, &request)
//	if err != nil {
//		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
//		return
//	}
//	csr, err := cert_service.GenCSR(request)
//	if err != nil {
//		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
//		return
//	}
//	g.Success(csr)
//}

// @Tags CA
// @Summary 吊销用户证书
// @Description Revoke a certificate
// @Param RevokeRequest body model.RevokeRequest true "证书主题"
// @Accept  json
// @Produce  json
// @Success 200 {object} Result.Result
// @Router /ca/revokeCert [post]
func RevokeCert(c *gin.Context) {
	g := Result.Gin{C: c}
	request := model.RevokeRequest{}
	err := util.Validator(c, &request, g)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	err = cert_service.RevokeCert(request)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	g.Success(nil)
}
