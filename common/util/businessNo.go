package util

import (
	"math/rand"
	"time"
)

var source = rand.NewSource(time.Now().UnixNano())

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

//生成固定长度的业务流水号
func RandBusinessNo(length int) string {
	sysId := "99711050000"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[source.Int63()%int64(len(charset))]
	}
	return sysId + string(b)
}
