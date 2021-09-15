package router

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/6/10 下午3:18
 */

import (
	_ "github.com/brilliance/ca/docs"
	v1 "github.com/brilliance/ca/router/api/v1"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// CreateRouter 生成路由
func CreateRouter() *gin.Engine {
	router := gin.Default()
	// swagger
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	//pprof.Register(router)
	//testGroup := router.Group("/test/")
	//testGroup.POST("/invokeTest", service.InvokeTest)

	caGroup := router.Group("/ca/")
	caGroup.POST("/newCa", v1.NewCA)
	caGroup.POST("/signCert", v1.SignCert)

	//certGroup := router.Group("/cert/")
	caGroup.POST("/revokeCert", v1.RevokeCert)
	//certGroup.POST("/genCSR", v1.GenCSR)

	keyGroup := router.Group("/key/")
	keyGroup.POST("/newKeyPair", v1.GenKeyPair)

	crlGroup := router.Group("/crl/")
	crlGroup.POST("/genCrl", v1.GenCrl)

	return router
}
