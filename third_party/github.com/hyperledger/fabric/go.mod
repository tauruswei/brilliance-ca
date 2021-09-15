module github.com/hyperledger/fabric

go 1.13

replace github.com/spf13/viper v1.8.1 => github.com/spf13/viper v1.7.1

replace go.uber.org/zap v1.18.1 => go.uber.org/zap v1.12.0

require (
	github.com/golang/protobuf v1.4.2
	github.com/hyperledger/fabric-amcl v0.0.0-20210603140002-2670f91851c8
	github.com/hyperledger/fabric-sdk-go v1.0.0 // indirect
	github.com/miekg/pkcs11 v1.0.3
	github.com/onsi/ginkgo v1.6.0
	github.com/onsi/gomega v1.9.0
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/pkg/errors v0.9.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/sykesm/zap-logfmt v0.0.4
	github.com/tauruswei/go-netsign v0.0.0-20210719104843-ad19de70b31a
	github.com/tjfoc/gmsm v1.4.1
	github.com/tjfoc/gmtls v1.2.1 // indirect
	go.uber.org/zap v1.18.1
	golang.org/x/crypto v0.0.0-20201012173705-84dcc777aaee
	google.golang.org/grpc v1.31.0
)
