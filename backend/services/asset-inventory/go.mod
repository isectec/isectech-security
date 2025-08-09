module github.com/isectech/backend/services/asset-inventory

go 1.21

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/lib/pq v1.10.9
	github.com/go-redis/redis/v8 v8.11.5
	github.com/prometheus/client_golang v1.17.0
	github.com/sirupsen/logrus v1.9.3
	github.com/golang-migrate/migrate/v4 v4.16.2
	github.com/spf13/viper v1.17.0
	github.com/stretchr/testify v1.8.4
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/gorm v1.25.5
	gorm.io/driver/postgres v1.5.4
)
