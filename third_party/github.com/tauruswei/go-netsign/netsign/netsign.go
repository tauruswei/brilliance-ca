// +build cnccgm

package netsign

/*
   #cgo CFLAGS: -I/usr/lib/
   #cgo LDFLAGS: -L/usr/lib/ -lrenhangapi
   #include "RHVerifyAPI.h"
   #include <stdio.h>
   #include <stdlib.h>
   #define CK_PTR *
   typedef unsigned char     CK_BYTE;
   typedef CK_BYTE*   CK_BYTE_PTR;
   typedef unsigned int CK_ULONG;
   typedef CK_ULONG CK_PTR CK_ULONG_PTR;
   typedef signed int CK_LONG;
   typedef CK_LONG CK_PTR CK_LONG_PTR;
*/
import "C"
import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
	"unsafe"
) // 注意这个地方与上面注释的地方不能有空行，并且不能使用括号如import ("C" "fmt")

type NetSign struct {
	Ip string
}

func (ns *NetSign) OpenNetSign(ip, password string, port int) (int, int) {
	ns.Ip = ip
	var socketFd C.int
	nsIp := C.CString(ip)
	defer C.free(unsafe.Pointer(nsIp))
	nsPassword := C.CString(password)
	defer C.free(unsafe.Pointer(nsPassword))
	ret := C.ConnToNetSign(nsIp, C.int(port), nsPassword, &socketFd)
	return int(socketFd), int(ret)
}
func (ns *NetSign) CloseNetSign(socketFd int) int {
	return int(C.DiscFromNetSign(C.int(socketFd)))
}

func (ns *NetSign) GenP10(socketFd int, certDN, keyLabel, keyType string) ([]byte, int) {
	nsCertDN := C.CString(certDN)
	defer C.free(unsafe.Pointer(nsCertDN))
	nsKeyLabel := C.CString(keyLabel)
	defer C.free(unsafe.Pointer(nsKeyLabel))
	nsKeyType := C.CString(keyType)
	defer C.free(unsafe.Pointer(nsKeyType))

	p10 := C.malloc(C.sizeof_uchar * 2048)
	defer C.free(unsafe.Pointer(p10))
	p10len := C.uint(2048)

	ret := C.INS_KPLGenP10Req(C.int(socketFd), nsCertDN, nsKeyLabel, nsKeyType, 0,
		(*C.uchar)(p10), &p10len)

	s := C.GoBytes(unsafe.Pointer(p10), C.int(p10len))
	return s, int(ret)
}
func (ns *NetSign) CheckResourceSynStatus(socketFd, netsignLen int, keyLabel string) ([]byte, int) {

	nsKeyLabel := C.CString(keyLabel)
	defer C.free(unsafe.Pointer(nsKeyLabel))

	p10 := C.malloc(C.sizeof_uchar * 1024)
	defer C.free(unsafe.Pointer(p10))
	p10len := C.uint(1024)

	ret := C.INS_KPLCheckResourceSynStatus(C.int(socketFd), 2, nsKeyLabel,
		(*C.char)(p10), &p10len)

	statusDesc := C.GoBytes(unsafe.Pointer(p10), C.int(p10len))
	return statusDesc, int(ret)
}
func (ns *NetSign) UploadCert(socketFd int, keyLabel string, certBytes []byte) int {
	nsKeyLabel := C.CString(keyLabel)
	defer C.free(unsafe.Pointer(nsKeyLabel))

	ret := C.INS_KPLImportCert(C.int(socketFd), nsKeyLabel, C.CK_BYTE_PTR(unsafe.Pointer(&certBytes[0])),
		C.uint(len(certBytes)))
	return int(ret)
}

func (ns *NetSign) Sign(socketFd, flag int, msg []byte, keyLabel, digestAlg string) ([]byte, int) {
	nsKeyLabel := C.CString(keyLabel)
	defer C.free(unsafe.Pointer(nsKeyLabel))
	alg := C.CString(digestAlg)
	defer C.free(unsafe.Pointer(alg))

	signResult := C.malloc(C.sizeof_uchar * 1024)
	defer C.free(unsafe.Pointer(signResult))
	signResultLen := C.int(1024)

	ret := C.INS_KPLRawSignData(C.int(socketFd), C.CK_BYTE_PTR(unsafe.Pointer(&msg[0])), C.int(len(msg)), nsKeyLabel,
		alg, C.int(flag), C.INS_ENCODING_BINARY, (*C.uchar)(signResult), &signResultLen)

	s := C.GoBytes(unsafe.Pointer(signResult), C.int(signResultLen))
	return s, int(ret)
}

func (ns *NetSign) Verify(socketFd, flag int, msg, signResult []byte, keyLabel, digestAlg string) int {
	nsKeyLabel := C.CString(keyLabel)
	defer C.free(unsafe.Pointer(nsKeyLabel))
	nsDigestAlg := C.CString(digestAlg)
	defer C.free(unsafe.Pointer(nsDigestAlg))

	sig := C.CK_BYTE_PTR(unsafe.Pointer(&signResult[0]))
	sigLen := C.int(len(signResult))

	ret := C.INS_KPLRawVerifyData(C.int(socketFd), C.CK_BYTE_PTR(unsafe.Pointer(&msg[0])), C.int(len(msg)), nsKeyLabel,
		nsDigestAlg, C.int(flag), C.INS_ENCODING_BINARY, sig, sigLen)
	return int(ret)
}

func (ns *NetSign) Hash(socketFd int, digestAlg string, pMsg []byte) ([]byte, int) {

	digest := C.malloc(C.sizeof_uchar * 64)
	defer C.free(unsafe.Pointer(digest))
	digestlen := C.int(64)
	nsDigestAlg := C.CString(digestAlg)
	defer C.free(unsafe.Pointer(nsDigestAlg))
	ret := int(C.INS_HashData(C.int(socketFd), nsDigestAlg, C.CK_BYTE_PTR(unsafe.Pointer(&pMsg[0])), C.CK_LONG(len(pMsg)),
		(*C.uchar)(digest), &digestlen))

	digest1 := C.GoBytes(unsafe.Pointer(digest), C.int(digestlen))
	return digest1, ret
}

func CheckAllNetsignStatus(address []string, len int) []int {
	time1 := os.Getenv("NETSIGN_TIME_OUT")
	if time1 == "" {
		time1 = "3"
	}
	timeout, err := strconv.Atoi(time1)
	if err != nil {
		timeout = 3
		panic("get netsign timeout error")
	}
	status := make([]int, len, len)
	for i, value := range address {
		conn, err := net.DialTimeout("tcp", value, time.Duration(timeout)*time.Second)
		if err == nil {
			if conn != nil {
				_ = conn.Close()
			}
			status[i] = 0
		} else {
			fmt.Println(err.Error())
			status[i] = 1
		}
	}
	return status
}
