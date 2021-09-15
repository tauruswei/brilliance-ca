package v1

import (
	"github.com/brilliance/ca/Result"
	"github.com/brilliance/ca/model"
	"github.com/brilliance/ca/service/crl_service"
	"github.com/gin-gonic/gin"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/9/10 下午3:52
 */
func GenCrl(c *gin.Context) {
	g := Result.Gin{C: c}
	request := model.CrlRequest{}
	err := model.GetBody(c.Request.Body, &request)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	crl, err := crl_service.GenCrl(request)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	g.Success(crl)
}