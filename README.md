# Dependency Scanner Service

A Go-based service that performs security analysis on Git repositories using OWASP Dependency Check. The service provides REST APIs to scan projects, check scan status, and retrieve vulnerability reports.

## Features

- Git repository scanning with OWASP Dependency Check
- Pulls repositories from any Git host and scans them with OWASP Dependency Check   
- Vulnerability results storage in PostgreSQL
- Kubernetes deployment support
- Persistent volume for NVD cache data
- Automated CI/CD with GitHub Actions

## Environment Variables

```env
DB_HOST=<postgresql-host>
DB_USER=<database-user>
DB_NAME=<database-name>
DB_PASSWORD=<database-password>
NVD_API_KEY=<your-nvd-api-key>
```

## Database Schema

The service uses two main tables:

### Scans Table
- `id` (UUID, Primary Key)
- `target` (VARCHAR(255)) - Repository URL to scan
- `scan_id` (VARCHAR(255)) - Unique scan identifier
- `status` (ENUM) - QUEUED, IN_PROGRESS, COMPLETED, FAILED
- `created_at` (TIMESTAMP)
- `completed_at` (TIMESTAMP)

### Scan Results Table
- `id` (UUID, Primary Key)
- `scan_id` (UUID, Foreign Key to Scans)
- `vulnerability_id` (VARCHAR(255))
- `severity` (ENUM) - LOW, MEDIUM, Moderate, HIGH, CRITICAL
- `description` (TEXT)
- `component` (VARCHAR(255))
- `created_at` (TIMESTAMP)

## API Endpoints

### Start a New Scan
```http
POST /api/scan/start
Content-Type: application/json

{
    "target": "https://github.com/user/repository"
}
```

### Check Scan Status
```http
GET /api/scan/status/{scanID}
```

### Save Scan Results
```http
POST /api/scan/save/{scanID}
```

### Get All Scan Results
```http
GET /api/scan/results
```

## Deployment

### Local Development
1. Clone the repository
2. Set up environment variables
3. Install dependencies:
   ```bash
   go mod download
   ```
4. Run the service:
   ```bash
   NVD_API_KEY=NVD_API_KEY DB_NAME=DB_NAME DB_USER=DB_USER DB_PASSWORD=DB_PASSWORD DB_HOST=DB_HOST go run cmd/api/main.go
   ```

### Kubernetes Deployment
1. Apply the kubernetes manifest files:
   ```bash
   kubectl apply -f k8s/
   ```

## CI/CD Pipeline

The project includes a GitHub Actions workflow that:

1. Builds the Go application
2. Runs security scans
4. Pushes image to GitHub Container Registry
5. Reports security findings to GitHub Security Advisory

## Testing

The service includes a Postman collection for API testing. Import `postman-collection.json` to your Postman workspace to get started.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For questions and support, contact: alptekine2@gmail.com