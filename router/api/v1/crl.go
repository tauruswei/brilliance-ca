package v1

import (
	"github.com/brilliance/ca/Result"
	"github.com/brilliance/ca/common/util"
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

// @Tags CRL
// @Summary 生成 crl
// @Description Gerate a crl
// @Param CrlRequest body model.CrlRequest true "证书主题"
// @Accept  json
// @Produce  json
// @Success 200 {object} Result.Result
// @Router /crl/genCrl [post]
func GenCrl(c *gin.Context) {
	g := Result.Gin{C: c}
	request := model.CrlRequest{}
	err := util.Validator(c, &request, g)
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
