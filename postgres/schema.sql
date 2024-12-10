CREATE TYPE scan_status AS ENUM ('QUEUED', 'IN_PROGRESS', 'COMPLETED', 'FAILED');
CREATE TYPE vulnerability_severity AS ENUM ('LOW','MEDIUM', 'MODERATE', 'HIGH', 'CRITICAL');

CREATE TABLE scans (
    id UUID PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    scan_id VARCHAR(255) NOT NULL UNIQUE,
    status scan_status NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE TABLE scan_results (
    id UUID PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    vulnerability_id VARCHAR(255) NOT NULL,
    severity vulnerability_severity NOT NULL,
    description TEXT NOT NULL,
    component VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scans_scan_id ON scans(scan_id);
CREATE INDEX idx_scan_results_scan_id ON scan_results(scan_id);
