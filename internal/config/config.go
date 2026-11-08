package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type Config struct {
	Env             string
	Port            string
	LogLevel        string
	FrontendURL     string
	SiteName        string
	SiteDescription string
	// SupportEmail receives partner applications.
	SupportEmail string

	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	// TrustedProxies 是允许设置 X-Forwarded-For 的上游代理（IP 或 CIDR）。
	TrustedProxies []string
	PowerDNS       PowerDNSConfig
	Email          EmailConfig
	Scanner        ScannerConfig
	Payment        PaymentConfig
	DNS            DNSConfig
	OAuth          OAuthConfig
	Telegram       TelegramConfig
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

type JWTConfig struct {
	Secret    string
	ExpiresIn int // hours
}

type PowerDNSConfig struct {
	APIURL string
	APIKey string
}

type EmailConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
}

type ScannerConfig struct {
	Concurrency           int
	Timeout               int // seconds
	GoogleSafeBrowsingKey string
	VirusTotalKey         string
}

type PaymentConfig struct {
	NodelocPaymentID string
	NodelocSecretKey string
	CallbackURL      string
	IsTestMode       bool
}

type DNSConfig struct {
	DefaultNS1 string
	DefaultNS2 string
}

type OAuthConfig struct {
	GithubClientID      string
	GithubClientSecret  string
	GoogleClientID      string
	GoogleClientSecret  string
	NodelocClientID     string
	NodelocClientSecret string
}

type TelegramConfig struct {
	BotToken  string
	ChannelID string
}

// Load 加载配置
func Load() (*Config, error) {
	// 加载 .env 文件
	_ = godotenv.Load()

	// 配置 Viper
	viper.AutomaticEnv()
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")

	// 尝试读取配置文件；文件不存在不是错误（纯环境变量部署也是合法的）
	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) && !os.IsNotExist(err) {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// 设置默认值
	setDefaults()

	cfg := &Config{
		Env:             viper.GetString("APP_ENV"),
		Port:            viper.GetString("PORT"),
		LogLevel:        viper.GetString("LOG_LEVEL"),
		FrontendURL:     viper.GetString("FRONTEND_URL"),
		SiteName:        viper.GetString("SITE_NAME"),
		SiteDescription: viper.GetString("SITE_DESCRIPTION"),
		SupportEmail:    viper.GetString("SUPPORT_EMAIL"),

		Database: DatabaseConfig{
			Host:     viper.GetString("DB_HOST"),
			Port:     viper.GetInt("DB_PORT"),
			User:     viper.GetString("DB_USER"),
			Password: viper.GetString("DB_PASSWORD"),
			DBName:   viper.GetString("DB_NAME"),
			SSLMode:  viper.GetString("DB_SSL_MODE"),
		},

		Redis: RedisConfig{
			Host:     viper.GetString("REDIS_HOST"),
			Port:     viper.GetInt("REDIS_PORT"),
			Password: viper.GetString("REDIS_PASSWORD"),
			DB:       viper.GetInt("REDIS_DB"),
		},

		TrustedProxies: parseTrustedProxies(viper.GetString("TRUSTED_PROXIES")),

		JWT: JWTConfig{
			Secret:    viper.GetString("JWT_SECRET"),
			ExpiresIn: viper.GetInt("JWT_EXPIRES_IN"),
		},

		PowerDNS: PowerDNSConfig{
			APIURL: viper.GetString("POWERDNS_API_URL"),
			APIKey: viper.GetString("POWERDNS_API_KEY"),
		},

		Email: EmailConfig{
			Host:     viper.GetString("MAIL_HOST"),
			Port:     viper.GetInt("MAIL_PORT"),
			User:     viper.GetString("MAIL_USER"),
			Password: viper.GetString("MAIL_PASSWORD"),
			From:     viper.GetString("MAIL_FROM"),
		},

		Scanner: ScannerConfig{
			Concurrency:           viper.GetInt("SCANNER_CONCURRENCY"),
			Timeout:               viper.GetInt("SCANNER_TIMEOUT"),
			GoogleSafeBrowsingKey: viper.GetString("GOOGLE_SAFE_BROWSING_KEY"),
			VirusTotalKey:         viper.GetString("VIRUSTOTAL_API_KEY"),
		},

		Payment: PaymentConfig{
			NodelocPaymentID: viper.GetString("NODELOC_PAYMENT_ID"),
			NodelocSecretKey: viper.GetString("NODELOC_SECRET_KEY"),
			CallbackURL:      viper.GetString("PAYMENT_CALLBACK_URL"),
			IsTestMode:       viper.GetBool("PAYMENT_TEST_MODE"),
		},

		DNS: DNSConfig{
			DefaultNS1: viper.GetString("DEFAULT_NS1"),
			DefaultNS2: viper.GetString("DEFAULT_NS2"),
		},

		OAuth: OAuthConfig{
			GithubClientID:      viper.GetString("GITHUB_CLIENT_ID"),
			GithubClientSecret:  viper.GetString("GITHUB_CLIENT_SECRET"),
			GoogleClientID:      viper.GetString("GOOGLE_CLIENT_ID"),
			GoogleClientSecret:  viper.GetString("GOOGLE_CLIENT_SECRET"),
			NodelocClientID:     viper.GetString("NODELOC_CLIENT_ID"),
			NodelocClientSecret: viper.GetString("NODELOC_CLIENT_SECRET"),
		},

		Telegram: TelegramConfig{
			BotToken:  viper.GetString("TELEGRAM_BOT_TOKEN"),
			ChannelID: viper.GetString("TELEGRAM_CHANNEL_ID"),
		},
	}

	if err := validateJWTSecret(cfg.JWT.Secret); err != nil {
		return nil, err
	}

	return cfg, nil
}

// defaultTrustedProxies 覆盖本机、Docker 内网以及 Cloudflare 边缘节点。
// 链路为 Cloudflare -> nginx -> docker-proxy -> app：只有这些地址追加的
// X-Forwarded-For 才会被采信，客户端自己伪造的部分会被忽略。
// Cloudflare 网段来源：https://www.cloudflare.com/ips/
var defaultTrustedProxies = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// parseTrustedProxies 解析逗号分隔的 TRUSTED_PROXIES；为空时使用默认列表。
func parseTrustedProxies(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), defaultTrustedProxies...)
	}
	return out
}

// minJWTSecretLength 是 HS256 密钥的最小长度（字节）。
const minJWTSecretLength = 32

// knownPlaceholderJWTSecrets 是仓库模板里出现过的占位密钥。任何人都能用它们
// 伪造 is_admin=true 的 token，因此一律拒绝启动。
var knownPlaceholderJWTSecrets = map[string]bool{
	"your-super-secret-jwt-key-change-this-in-production": true,
	"change-this-secret-key":                              true,
	"dev-secret-key":                                      true,
}

// validateJWTSecret 拒绝空的、模板默认的或过短的 JWT 密钥。
func validateJWTSecret(secret string) error {
	const hint = "generate one with: openssl rand -hex 48"
	switch {
	case secret == "":
		return fmt.Errorf("JWT_SECRET is not set; %s", hint)
	case knownPlaceholderJWTSecrets[secret]:
		return fmt.Errorf("JWT_SECRET is a published placeholder value and must be replaced; %s", hint)
	case len(secret) < minJWTSecretLength:
		return fmt.Errorf("JWT_SECRET must be at least %d characters; %s", minJWTSecretLength, hint)
	}
	return nil
}

func setDefaults() {
	viper.SetDefault("APP_ENV", "development")
	viper.SetDefault("PORT", "8000")
	viper.SetDefault("LOG_LEVEL", "debug")

	viper.SetDefault("DB_HOST", "localhost")
	viper.SetDefault("DB_PORT", 5432)
	viper.SetDefault("DB_SSL_MODE", "disable")

	viper.SetDefault("REDIS_HOST", "localhost")
	viper.SetDefault("REDIS_PORT", 6379)
	viper.SetDefault("REDIS_DB", 0)

	viper.SetDefault("JWT_EXPIRES_IN", 168)

	viper.SetDefault("SCANNER_CONCURRENCY", 10)
	viper.SetDefault("SCANNER_TIMEOUT", 30)

	viper.SetDefault("SITE_NAME", "Yunamo")
	viper.SetDefault("SITE_DESCRIPTION", "Your dynamo starts with a name")
	viper.SetDefault("FRONTEND_URL", "http://localhost:3001")
	viper.SetDefault("SUPPORT_EMAIL", "support@yunamo.com")
	viper.SetDefault("PAYMENT_CALLBACK_URL", fmt.Sprintf("http://localhost:%s/api/payments/callback", viper.GetString("PORT")))
	viper.SetDefault("PAYMENT_TEST_MODE", false)

	viper.SetDefault("DEFAULT_NS1", "ns1.nodelook.com")
	viper.SetDefault("DEFAULT_NS2", "ns2.nodelook.com")

}

// InitDatabase 初始化数据库连接
func InitDatabase(cfg *Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=UTC",
		cfg.Database.Host,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.DBName,
		cfg.Database.Port,
		cfg.Database.SSLMode,
	)

	// 设置日志级别
	logLevel := gormlogger.Silent
	if cfg.Env == "development" {
		logLevel = gormlogger.Info
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(logLevel),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	// 设置连接池
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// InitRedis 初始化 Redis 连接
func InitRedis(cfg *Config) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return client, nil
}
