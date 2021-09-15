package netsign

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/17 下午4:30
 */
func TestNetSign_CloseNetSign(t *testing.T) {
	ns := NetSign{}
	socketFd, ret := ns.OpenNetSign("47.105.180.88", "CNCC123456", 19443)
	if ret != 0 {
		fmt.Println("open netsign error")
	}
	p10, ret := ns.GenP10(socketFd, "CN=brilliance", "test", "SM2")
	if ret != 0 {
		fmt.Println("generate p10 error")
	}

	ret = ns.UploadCert(socketFd, "test", p10)
	if ret != 0 {
		fmt.Println("upload cert error")
	}
	sign, ret := ns.Sign(socketFd, 0, []byte("hello world"), "test", "sm3")
	if ret != 0 {
		fmt.Println("sign error")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(sign))
	ret = ns.Verify(socketFd, 1, []byte("hello world"), sign, "test", "sm3")
	if ret != 0 {
		fmt.Println("verify error")
	}

}
func TestCheckAllNetsignStatus(t *testing.T) {
	address := make([]string, 4, 4)
	address[0] = net.JoinHostPort("47.105.180.88", "19443")
	address[1] = net.JoinHostPort("47.105.180.88", "19444")
	address[2] = net.JoinHostPort("47.105.180.88", "19445")
	address[3] = net.JoinHostPort("47.105.180.88", "19446")
	status := CheckAllNetsignStatus(address, 4)
	for i, i2 := range status {
		fmt.Println(i, i2)
	}

}
func TestNetSign_OpenNetSign(t *testing.T) {
	sign := NetSign{Ip: "39.100.115.152"}
	netSign, i := sign.OpenNetSign(sign.Ip, "12314", 34998)
	fmt.Println(netSign)
	fmt.Println(i)

}

func TestNetSign(t *testing.T) {
	ip := "39.100.115.152"
	password := "123456"
	port := 35000
	ns := NetSign{}
	socketFd, ret1 := ns.OpenNetSign(ip, password, port)
	if ret1 != 0 {
		fmt.Printf("netsign open error: ret[%d],ip[%s],port[%d],password[%s]\n", ret1, ip, port, password)
	}
	ret2 := ns.CloseNetSign(socketFd)
	if ret2 != 0 {
		fmt.Printf("netsign close error: ret[%d],ip[%s],port[%d],password[%s]\n", ret2, ip, port, password)
	}
	fmt.Println("success")
}
