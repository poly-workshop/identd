# Client Credentials

Client credentials are used to authenticate external services that need to interact with Identra's authentication system using the OAuth2 Client Credentials flow.

## Overview

Client credentials consist of:

- **Client ID**: A unique identifier for the client (32-character hex string)
- **Client Secret**: A secret key for authentication (64-character hex string)

## CLI Tool

The `identra-cli` tool is used to manage client credentials. It does not require the gRPC or gateway servers to be running.

### Building the CLI

```bash
make build-cli
# or
go build -o bin/identra-cli ./cmd/cli
```

### Available Commands

#### Create a new credential

```bash
./bin/cli create --name "My Service" --description "External service integration" --scopes "read,write"
```

Options:

- `-n, --name` (required): Name of the client credential
- `-d, --description`: Description of the client credential
- `-s, --scopes`: Comma-separated list of scopes
- `-e, --expires`: Number of days until expiration (0 = no expiration)

**Important**: Save the client secret immediately after creation. It will not be shown again.

#### List all credentials

```bash
./bin/cli list
./bin/cli list --limit 50
```

#### Get credential details

```bash
./bin/cli get <id|client_id>
```

#### Delete a credential

```bash
./bin/cli delete <id|client_id>
./bin/cli delete <id|client_id> --force  # Skip confirmation
```

#### Rotate client secret

```bash
./bin/cli rotate <id|client_id>
```

This generates a new client secret and invalidates the old one.

#### Activate/Deactivate a credential

```bash
./bin/cli deactivate <id|client_id>
./bin/cli activate <id|client_id>
```

Deactivating a credential temporarily prevents it from being used without deleting it.

## Configuration

The CLI uses the same configuration format as other Identra components. Create a config file at `configs/cli/default.toml`:

```toml
[gorm_client.database]
driver = "sqlite"
name = "data/users.db"
sslmode = "disable"
```

For PostgreSQL:

```toml
[gorm_client.database]
driver = "postgres"
host = "localhost"
port = 5432
username = "postgres"
password = "password"
name = "identra"
sslmode = "disable"
```

## Security Considerations

1. **Client secrets are hashed**: The client secret is never stored in plain text. It's hashed using Argon2ID.
2. **Secrets shown only once**: The client secret is only displayed when creating or rotating credentials.
3. **Expiration support**: Set an expiration date to automatically invalidate credentials.
4. **Deactivation**: Credentials can be deactivated without deletion for temporary suspension.
5. **Audit trail**: `last_used_at` timestamp tracks when credentials were last used.

## Database Schema

The client credentials are stored in the `client_credentials` table:

| Column | Type | Description |
|--------|------|-------------|
| id | VARCHAR(36) | Primary key (UUID) |
| client_id | VARCHAR(64) | Unique client identifier |
| hashed_client_secret | VARCHAR(255) | Argon2ID hashed secret |
| name | VARCHAR(255) | Human-readable name |
| description | TEXT | Optional description |
| scopes | TEXT | Comma-separated scopes |
| is_active | BOOLEAN | Whether the credential is active |
| last_used_at | TIMESTAMP | Last usage timestamp |
| expires_at | TIMESTAMP | Optional expiration timestamp |
| created_at | TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | Last update timestamp |
| deleted_at | TIMESTAMP | Soft delete timestamp |

## Usage in External Services

External services must provide client credentials in the HTTP headers when making requests to the Identra API:

- `X-Client-Id`: Your Client ID
- `X-Client-Secret`: Your Client Secret

Example request:

```bash
curl -X POST https://your-identra-server/api/v1/oauth/login \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: YOUR_CLIENT_ID" \
  -H "X-Client-Secret: YOUR_CLIENT_SECRET" \
  -d '{"code": "...", "state": "..."}'
```

These headers are required for:

- OAuth Login (`/v1/oauth/login`)
- Password Login (`/v1/password/login`)
- Token Refresh (`/v1/token/refresh`)
