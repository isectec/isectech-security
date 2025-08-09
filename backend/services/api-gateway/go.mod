module github.com/isectech/platform/services/api-gateway

go 1.21

replace github.com/isectech/platform => ../../

require (
	github.com/isectech/platform v0.0.0-00010101000000-000000000000
	github.com/gin-gonic/gin v1.9.1
	github.com/prometheus/client_golang v1.17.0
	go.uber.org/zap v1.26.0
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.31.0
	github.com/stretchr/testify v1.8.4
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/sony/gobreaker v0.5.0
	github.com/google/uuid v1.4.0
	github.com/go-redis/redis/v8 v8.11.5
	golang.org/x/time v0.5.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.1
)