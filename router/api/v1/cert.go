package v1

import (
	"github.com/brilliance/ca/Result"
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

// @Summary Create a new CA certificate
// @Consume  json
// @Produce  json
// @Success 200 {object} app.Response
// @Failure 500 {object} app.Response
// @Router /api/v1/articles/{id} [get]
func NewCA(c *gin.Context) {
	g := Result.Gin{C: c}
	request := model.CertificateRequest{}
	err := model.GetBody(c.Request.Body, &request)
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

func SignCert(c *gin.Context) {
	g := Result.Gin{C: c}
	request := model.SignCertRequest{}
	err := model.GetBody(c.Request.Body, &request)
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
func RevokeCert(c *gin.Context) {
	g := Result.Gin{C: c}
	request := model.RevokeRequest{}
	err := model.GetBody(c.Request.Body, &request)
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

