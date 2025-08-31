package interceptor

import (
	"context"
	"log/slog"

	"github.com/poly-workshop/identra/internal/repository"
	"github.com/poly-workshop/identra/internal/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

// ClientCredentialInterceptor validates client credentials in gRPC metadata
func ClientCredentialInterceptor(
	credRepo repository.ClientCredentialRepository,
	protectedMethods map[string]bool,
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if the method requires client credential validation
		if !protectedMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract client credentials from metadata
		clientID, clientSecret := extractClientCredentials(ctx)
		if clientID == "" || clientSecret == "" {
			return nil, status.Error(codes.InvalidArgument, "client_id and client_secret are required")
		}

		// Validate credentials
		cred, err := credRepo.GetByClientID(ctx, clientID)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil, status.Error(codes.Unauthenticated, "invalid client credentials")
			}
			return nil, status.Errorf(codes.Internal, "failed to validate client credentials: %v", err)
		}

		if !cred.IsValid() {
			return nil, status.Error(codes.Unauthenticated, "client credential is inactive or expired")
		}

		valid, err := utils.VerifyClientSecret(clientSecret, cred.HashedClientSecret)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to verify client secret: %v", err)
		}

		if !valid {
			return nil, status.Error(codes.Unauthenticated, "invalid client credentials")
		}

		// Update last used timestamp asynchronously
		go func() {
			if err := credRepo.UpdateLastUsed(context.Background(), cred.ID); err != nil {
				slog.Error("failed to update client credential last used timestamp", "error", err, "id", cred.ID)
			}
		}()

		return handler(ctx, req)
	}
}

// extractClientCredentials extracts client_id and client_secret from gRPC metadata
func extractClientCredentials(ctx context.Context) (string, string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ""
	}

	clientID := ""
	if ids := md.Get("x-client-id"); len(ids) > 0 {
		clientID = ids[0]
	}

	clientSecret := ""
	if secrets := md.Get("x-client-secret"); len(secrets) > 0 {
		clientSecret = secrets[0]
	}

	return clientID, clientSecret
}
