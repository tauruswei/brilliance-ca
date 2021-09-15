package Result

import "fmt"

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2021/9/8 下午11:02
 */
type CodeMsg struct {
	Code int
	Msg  string
}

func (codemsg CodeMsg) FillArgs(args ...string) CodeMsg{
	codemsg.Msg = fmt.Sprintf(codemsg.Msg, args)
	return codemsg
}

var (
	SUCCESS      = CodeMsg{Code: 0, Msg: "SUCCESS"}
	SERVER_ERROR = CodeMsg{Code: 500100, Msg: "服务端异常: %s"}
)
