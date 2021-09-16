module github.com/brilliance/ca

go 1.13

replace github.com/tjfoc/gmsm v1.4.1 => ./internal/github.com/tjfoc/gmsm

replace github.com/tjfoc/gmtls v1.2.1 => ./internal/github.com/tjfoc/gmtls

replace github.com/hyperledger/fabric => ./third_party/github.com/hyperledger/fabric

replace github.com/tauruswei/go-netsign => ./third_party/github.com/tauruswei/go-netsign

replace github.com/spf13/viper v1.8.1 => github.com/spf13/viper v1.7.1

require (
	github.com/EDDYCJY/go-gin-example v0.0.0-20201228125222-28f372bf41f9 // indirect
	github.com/astaxie/beego v1.12.3 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/gin-gonic/gin v1.7.4
	github.com/go-openapi/jsonreference v0.19.6 // indirect
	github.com/go-openapi/swag v0.19.15 // indirect
	github.com/go-playground/locales v0.13.0
	github.com/go-playground/pool v3.1.1+incompatible // indirect
	github.com/go-playground/universal-translator v0.17.0
	github.com/go-playground/validator/v10 v10.4.1
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hyperledger/fabric v1.4.12
	github.com/jinzhu/gorm v1.9.16 // indirect
	github.com/jmoiron/sqlx v0.0.0-20180124204410-05cef0741ade
	github.com/kylelemons/go-gypsy v1.0.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/pkg/errors v0.9.1
	github.com/spf13/viper v1.8.1
	github.com/swaggo/files v0.0.0-20190704085106-630677cd5c14
	github.com/swaggo/gin-swagger v1.3.1
	github.com/swaggo/swag v1.7.1
	github.com/thedevsaddam/gojsonq v2.3.0+incompatible
	github.com/tjfoc/gmsm v1.4.1
	github.com/unrolled/secure v1.0.9
	github.com/urfave/cli v1.22.5 // indirect
	golang.org/x/net v0.0.0-20210913180222-943fd674d43e // indirect
	golang.org/x/sys v0.0.0-20210915083310-ed5796bab164 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.1.5 // indirect
	gorm.io/driver/mysql v1.1.2
	gorm.io/gorm v1.21.15
)
