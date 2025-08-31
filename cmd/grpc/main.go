package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/poly-workshop/go-webmods/app"
	gorm_client "github.com/poly-workshop/go-webmods/gorm-client"
	grpc_utils "github.com/poly-workshop/go-webmods/grpc-utils"
	redis_client "github.com/poly-workshop/go-webmods/redis-client"
	identra_v1_pb "github.com/poly-workshop/identra/gen/proto/identra/v1"
	"github.com/poly-workshop/identra/internal/configs"
	"github.com/poly-workshop/identra/internal/interceptor"
	"github.com/poly-workshop/identra/internal/model"
	"github.com/poly-workshop/identra/internal/repository"
	"github.com/poly-workshop/identra/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func init() {
	app.Init("grpc")
}

// InterceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(
		func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
			l.Log(ctx, slog.Level(lvl), msg, fields...)
		},
	)
}

func main() {
	cfg := configs.Load()

	// Initialize database
	db := gorm_client.NewDB(cfg.Database)
	err := db.AutoMigrate(&model.UserModel{}, &model.ClientCredentialModel{})
	if err != nil {
		slog.Error("failed to migrate database", "error", err)
	}

	// Initialize Redis client
	redis_client.SetConfig(cfg.Redis.Urls, cfg.Redis.Password)
	rdb := redis_client.GetRDB()

	// Initialize repositories and services
	credRepo := repository.NewClientCredentialRepository(db)
	authService := service.NewAuthService(db, rdb, credRepo)

	// Define methods that require client credentials
	clientCredMethods := map[string]bool{
		identra_v1_pb.IdentraService_LoginByOAuth_FullMethodName:    true,
		identra_v1_pb.IdentraService_LoginByPassword_FullMethodName: true,
		identra_v1_pb.IdentraService_RefreshToken_FullMethodName:    true,
	}

	// Setup gRPC server with auth interceptor
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpc_utils.BuildRequestIDInterceptor(),
			logging.UnaryServerInterceptor(InterceptorLogger(slog.Default())),
			interceptor.ClientCredentialInterceptor(credRepo, clientCredMethods),
		),
	)
	identra_v1_pb.RegisterIdentraServiceServer(grpcServer, authService)
	reflection.Register(grpcServer)

	// Start gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
	if err != nil {
		log.Fatalf("failed to listen on gRPC port: %v", err)
	}

	slog.Info("gRPC server started", "port", cfg.Server.Port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve gRPC: %v", err)
	}
}

func NewDB(cfg configs.Config) *gorm.DB {
	driver := cfg.Database.Driver
	switch driver {
	case "postgres":
		db, err := openPostgres(cfg)
		if err != nil {
			panic(err)
		}
		return db
	default:
		panic(fmt.Sprintf("unsupported database driver: %s", driver))
	}
}

func openPostgres(cfg configs.Config) (db *gorm.DB, err error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Username,
		cfg.Database.Name,
		cfg.Database.Password,
		cfg.Database.SSLMode,
	)
	db, err = gorm.Open(postgres.Open(dsn))
	if err != nil {
		return nil, err
	}
	return db, nil
}
