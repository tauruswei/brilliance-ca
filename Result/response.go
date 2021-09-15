package Result

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type Gin struct {
	C *gin.Context
}


type Result struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

func(g *Gin) Success(data interface{}){
	g.C.JSON(http.StatusOK,Result{Code:SUCCESS.Code,Msg:SUCCESS.Msg,Data:data})
	return
}

func (g *Gin) Error(codeMsg CodeMsg){
	g.C.JSON(http.StatusOK,Result{Code:codeMsg.Code,Msg:codeMsg.Msg})
	return
}

