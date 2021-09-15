package v1

import (
	"github.com/brilliance/ca/Result"
	"github.com/brilliance/ca/model"
	"github.com/brilliance/ca/service/key_service"
	"github.com/gin-gonic/gin"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/9/10 下午3:52
 */

// @Tags KEY
// @Summary 生成 keypair
// @Description Gerate a keypair
// @Param KeyRequest body model.KeyRequest true "密钥参数"
// @Accept  json
// @Produce  json
// @Success 200 {object} Result.Result
// @Router /key/newKeyPair [post]
func GenKeyPair(c *gin.Context) {
	g := Result.Gin{C: c}
	request := model.KeyRequest{}
	err := model.GetBody(c.Request.Body, &request)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	ca, err := key_service.GenKeyPair(request)
	if err != nil {
		g.Error(Result.SERVER_ERROR.FillArgs(err.Error()))
		return
	}
	g.Success(ca)
}
