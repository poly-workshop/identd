package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/poly-workshop/go-webmods/app"
	gorm_client "github.com/poly-workshop/go-webmods/gorm-client"
	"github.com/poly-workshop/identra/internal/configs"
	"github.com/poly-workshop/identra/internal/model"
	"github.com/poly-workshop/identra/internal/repository"
	"github.com/poly-workshop/identra/internal/utils"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

var (
	db       = initDB()
	credRepo = repository.NewClientCredentialRepository(db)
)

func initDB() *gorm.DB {
	app.Init("cli")
	cfg := configs.Load()
	db := gorm_client.NewDB(cfg.Database)
	// Auto-migrate the client credential model
	err := db.AutoMigrate(&model.ClientCredentialModel{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to migrate database: %v\n", err)
		os.Exit(1)
	}
	return db
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "identra-cli",
		Short: "Identra CLI - Manage client credentials for external services",
		Long: `Identra CLI is a command-line tool for managing OAuth2 client credentials.
It allows you to create, list, delete, and rotate client credentials for external services
that need to authenticate with the Identra authentication system.`,
	}

	// Add subcommands
	rootCmd.AddCommand(createCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(getCmd())
	rootCmd.AddCommand(deleteCmd())
	rootCmd.AddCommand(rotateCmd())
	rootCmd.AddCommand(deactivateCmd())
	rootCmd.AddCommand(activateCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func createCmd() *cobra.Command {
	var name, description, scopes string
	var expiresInDays int

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new client credential",
		Long:  `Create a new OAuth2 client credential for an external service.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("name is required")
			}

			// Generate client ID and secret
			clientID, err := utils.GenerateClientID()
			if err != nil {
				return fmt.Errorf("failed to generate client ID: %w", err)
			}

			clientSecret, err := utils.GenerateClientSecret()
			if err != nil {
				return fmt.Errorf("failed to generate client secret: %w", err)
			}

			// Hash the client secret
			hashedSecret, err := utils.HashClientSecret(clientSecret)
			if err != nil {
				return fmt.Errorf("failed to hash client secret: %w", err)
			}

			// Create the credential
			credential := &model.ClientCredentialModel{
				ClientID:           clientID,
				HashedClientSecret: hashedSecret,
				Name:               name,
				Description:        description,
				Scopes:             scopes,
				IsActive:           true,
			}

			// Set expiration if specified
			if expiresInDays > 0 {
				expiresAt := time.Now().AddDate(0, 0, expiresInDays)
				credential.ExpiresAt = &expiresAt
			}

			ctx := context.Background()
			if err := credRepo.Create(ctx, credential); err != nil {
				return fmt.Errorf("failed to create client credential: %w", err)
			}

			// Output the credentials (only time the secret is shown)
			fmt.Println("Client credential created successfully!")
			fmt.Println()
			fmt.Println("╔════════════════════════════════════════════════════════════════════╗")
			fmt.Println("║  IMPORTANT: Save these credentials now! The secret will not be     ║")
			fmt.Println("║  shown again.                                                      ║")
			fmt.Println("╚════════════════════════════════════════════════════════════════════╝")
			fmt.Println()
			fmt.Printf("ID:            %s\n", credential.ID)
			fmt.Printf("Name:          %s\n", credential.Name)
			fmt.Printf("Client ID:     %s\n", clientID)
			fmt.Printf("Client Secret: %s\n", clientSecret)
			if credential.ExpiresAt != nil {
				fmt.Printf("Expires At:    %s\n", credential.ExpiresAt.Format(time.RFC3339))
			}
			if scopes != "" {
				fmt.Printf("Scopes:        %s\n", scopes)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "Name of the client credential (required)")
	cmd.Flags().StringVarP(&description, "description", "d", "", "Description of the client credential")
	cmd.Flags().StringVarP(&scopes, "scopes", "s", "", "Comma-separated list of scopes")
	cmd.Flags().IntVarP(&expiresInDays, "expires", "e", 0, "Number of days until expiration (0 = no expiration)")

	return cmd
}

func listCmd() *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all client credentials",
		Long:  `List all OAuth2 client credentials with their details.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			credentials, err := credRepo.List(ctx, 0, limit)
			if err != nil {
				return fmt.Errorf("failed to list credentials: %w", err)
			}

			if len(credentials) == 0 {
				fmt.Println("No client credentials found.")
				return nil
			}

			// Create tabwriter for formatted output
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tNAME\tCLIENT_ID\tACTIVE\tEXPIRES\tLAST_USED")
			_, _ = fmt.Fprintln(w, "──\t────\t─────────\t──────\t───────\t─────────")

			for _, cred := range credentials {
				expiresStr := "Never"
				if cred.ExpiresAt != nil {
					expiresStr = cred.ExpiresAt.Format("2006-01-02")
				}

				lastUsedStr := "Never"
				if cred.LastUsedAt != nil {
					lastUsedStr = cred.LastUsedAt.Format("2006-01-02 15:04")
				}

				activeStr := "Yes"
				if !cred.IsActive {
					activeStr = "No"
				}

				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					cred.ID[:8]+"...",
					truncate(cred.Name, 20),
					cred.ClientID[:16]+"...",
					activeStr,
					expiresStr,
					lastUsedStr,
				)
			}
			_ = w.Flush()

			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "l", 100, "Maximum number of credentials to list")

	return cmd
}

func getCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <id|client_id>",
		Short: "Get details of a client credential",
		Long:  `Get detailed information about a specific client credential.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			identifier := args[0]

			var credential *model.ClientCredentialModel
			var err error

			// Try to find by ID first, then by client_id
			credential, err = credRepo.GetByID(ctx, identifier)
			if err != nil {
				credential, err = credRepo.GetByClientID(ctx, identifier)
				if err != nil {
					return fmt.Errorf("credential not found: %w", err)
				}
			}

			fmt.Printf("ID:          %s\n", credential.ID)
			fmt.Printf("Name:        %s\n", credential.Name)
			fmt.Printf("Client ID:   %s\n", credential.ClientID)
			fmt.Printf("Description: %s\n", credential.Description)
			fmt.Printf("Scopes:      %s\n", credential.Scopes)
			fmt.Printf("Active:      %v\n", credential.IsActive)
			fmt.Printf("Created At:  %s\n", credential.CreatedAt.Format(time.RFC3339))
			fmt.Printf("Updated At:  %s\n", credential.UpdatedAt.Format(time.RFC3339))

			if credential.ExpiresAt != nil {
				fmt.Printf("Expires At:  %s\n", credential.ExpiresAt.Format(time.RFC3339))
				if credential.IsExpired() {
					fmt.Println("             ⚠️  EXPIRED")
				}
			} else {
				fmt.Println("Expires At:  Never")
			}

			if credential.LastUsedAt != nil {
				fmt.Printf("Last Used:   %s\n", credential.LastUsedAt.Format(time.RFC3339))
			} else {
				fmt.Println("Last Used:   Never")
			}

			return nil
		},
	}

	return cmd
}

func deleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete <id|client_id>",
		Short: "Delete a client credential",
		Long:  `Delete a client credential by its ID or client_id.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			identifier := args[0]

			var credential *model.ClientCredentialModel
			var err error

			// Try to find by ID first, then by client_id
			credential, err = credRepo.GetByID(ctx, identifier)
			if err != nil {
				credential, err = credRepo.GetByClientID(ctx, identifier)
				if err != nil {
					return fmt.Errorf("credential not found: %w", err)
				}
			}

			if !force {
				fmt.Printf("Are you sure you want to delete credential '%s' (ID: %s)? [y/N]: ", credential.Name, credential.ID)
				var confirm string
				_, _ = fmt.Scanln(&confirm)
				if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
					fmt.Println("Deletion cancelled.")
					return nil
				}
			}

			if err := credRepo.Delete(ctx, credential.ID); err != nil {
				return fmt.Errorf("failed to delete credential: %w", err)
			}

			fmt.Printf("Client credential '%s' deleted successfully.\n", credential.Name)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func rotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate <id|client_id>",
		Short: "Rotate the client secret",
		Long:  `Generate a new client secret for an existing credential. The old secret will be invalidated.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			identifier := args[0]

			var credential *model.ClientCredentialModel
			var err error

			// Try to find by ID first, then by client_id
			credential, err = credRepo.GetByID(ctx, identifier)
			if err != nil {
				credential, err = credRepo.GetByClientID(ctx, identifier)
				if err != nil {
					return fmt.Errorf("credential not found: %w", err)
				}
			}

			// Generate new secret
			newSecret, err := utils.GenerateClientSecret()
			if err != nil {
				return fmt.Errorf("failed to generate new secret: %w", err)
			}

			// Hash the new secret
			hashedSecret, err := utils.HashClientSecret(newSecret)
			if err != nil {
				return fmt.Errorf("failed to hash new secret: %w", err)
			}

			// Update the credential
			credential.HashedClientSecret = hashedSecret
			if err := credRepo.Update(ctx, credential); err != nil {
				return fmt.Errorf("failed to update credential: %w", err)
			}

			fmt.Println("Client secret rotated successfully!")
			fmt.Println()
			fmt.Println("╔════════════════════════════════════════════════════════════════════╗")
			fmt.Println("║  IMPORTANT: Save the new secret now! It will not be shown again.   ║")
			fmt.Println("╚════════════════════════════════════════════════════════════════════╝")
			fmt.Println()
			fmt.Printf("Name:              %s\n", credential.Name)
			fmt.Printf("Client ID:         %s\n", credential.ClientID)
			fmt.Printf("New Client Secret: %s\n", newSecret)

			return nil
		},
	}

	return cmd
}

func deactivateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deactivate <id|client_id>",
		Short: "Deactivate a client credential",
		Long:  `Deactivate a client credential without deleting it. The credential can be reactivated later.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			identifier := args[0]

			var credential *model.ClientCredentialModel
			var err error

			// Try to find by ID first, then by client_id
			credential, err = credRepo.GetByID(ctx, identifier)
			if err != nil {
				credential, err = credRepo.GetByClientID(ctx, identifier)
				if err != nil {
					return fmt.Errorf("credential not found: %w", err)
				}
			}

			credential.IsActive = false
			if err := credRepo.Update(ctx, credential); err != nil {
				return fmt.Errorf("failed to deactivate credential: %w", err)
			}

			fmt.Printf("Client credential '%s' deactivated successfully.\n", credential.Name)
			return nil
		},
	}

	return cmd
}

func activateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "activate <id|client_id>",
		Short: "Activate a client credential",
		Long:  `Activate a previously deactivated client credential.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			identifier := args[0]

			var credential *model.ClientCredentialModel
			var err error

			// Try to find by ID first, then by client_id
			credential, err = credRepo.GetByID(ctx, identifier)
			if err != nil {
				credential, err = credRepo.GetByClientID(ctx, identifier)
				if err != nil {
					return fmt.Errorf("credential not found: %w", err)
				}
			}

			credential.IsActive = true
			if err := credRepo.Update(ctx, credential); err != nil {
				return fmt.Errorf("failed to activate credential: %w", err)
			}

			fmt.Printf("Client credential '%s' activated successfully.\n", credential.Name)
			return nil
		},
	}

	return cmd
}

// truncate truncates a string to the specified length, adding "..." if truncated
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
