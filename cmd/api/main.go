package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Scan struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key"`
	Target      string    `gorm:"type:varchar(255);not null"`
	ScanID      string    `gorm:"column:scan_id;type:varchar(255);not null;unique"`
	Status      string    `gorm:"type:scan_status;not null"`
	CreatedAt   time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
	CompletedAt *time.Time
}

type ScanResult struct {
	ID              uuid.UUID `gorm:"type:uuid;primary_key"`
	ScanID          uuid.UUID `gorm:"type:uuid;index"`
	VulnerabilityID string    `gorm:"type:varchar(255);not null"`
	Severity        string    `gorm:"type:vulnerability_severity;not null"`
	Description     string    `gorm:"type:text;not null"`
	Component       string    `gorm:"type:varchar(255);not null"`
	CreatedAt       time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
}

type StartScanRequest struct {
	Target string `json:"target"`
}

var (
	db         *gorm.DB
	storageDir string = "/dependency-check/data/repos"
	resultsDir string = "/dependency-check/data/results"
)

func init() {
	var err error
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s password=%s port=5432 sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PASSWORD"))

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	for _, dir := range []string{storageDir, resultsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}
}

func startScan(w http.ResponseWriter, r *http.Request) {
	var req StartScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scan := Scan{
		ID:        uuid.New(),
		Target:    req.Target,
		ScanID:    uuid.New().String(),
		Status:    "QUEUED",
		CreatedAt: time.Now(),
	}

	if result := db.Create(&scan); result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	go func() {
		repoDir := filepath.Join(storageDir, scan.ScanID)
		if err := os.MkdirAll(repoDir, 0755); err != nil {
			log.Printf("Error creating repository directory: %v", err)
			updateScanStatus(scan.ID, "FAILED")
			return
		}

		_, err := git.PlainClone(repoDir, false, &git.CloneOptions{
			URL:      req.Target,
			Progress: os.Stdout,
		})
		if err != nil {
			log.Printf("Error cloning repository: %v", err)
			updateScanStatus(scan.ID, "FAILED")
			return
		}

		updateScanStatus(scan.ID, "IN_PROGRESS")

		resultFile := filepath.Join(resultsDir, fmt.Sprintf("scan-result-%s.json", scan.ScanID))
		cmd := exec.Command("dependency-check.sh",
			"--project", filepath.Base(req.Target),
			"--scan", repoDir,
			"--nvdApiKey", os.Getenv("NVD_API_KEY"),
			"--format", "JSON",
			"--out", resultFile)

		var outb, errb bytes.Buffer
		cmd.Stdout = &outb
		cmd.Stderr = &errb

		if err := cmd.Run(); err != nil {
			log.Printf("Error running scan: %v\nStdout: %s\nStderr: %s",
				err, outb.String(), errb.String())
			updateScanStatus(scan.ID, "FAILED")
			return
		}

		updateScanStatus(scan.ID, "COMPLETED")
	}()

	json.NewEncoder(w).Encode(scan)
}

func getScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scanID"]

	var scan Scan
	result := db.Where("scan_id = ?", scanID).First(&scan)

	if result.Error != nil {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(scan)
}

func saveScanResults(w http.ResponseWriter, r *http.Request) {
	// implement this
	w.WriteHeader(http.StatusCreated)
}

func getScanResults(w http.ResponseWriter, r *http.Request) {
	var results []ScanResult
	if result := db.Find(&results); result.Error != nil {
		http.Error(w, "Failed to fetch scan results", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(results)
}

func updateScanStatus(scanID uuid.UUID, status string) {
	now := time.Now()
	db.Model(&Scan{}).
		Where("id = ? AND status != ?", scanID, "COMPLETED").
		Updates(map[string]interface{}{
			"status":       status,
			"completed_at": now,
		})
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/api/scan/start", startScan).Methods("POST")
	router.HandleFunc("/api/scan/status/{scanID}", getScanStatus).Methods("GET")
	router.HandleFunc("/api/scan/save", saveScanResults).Methods("POST")
	router.HandleFunc("/api/scan/results", getScanResults).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", router))
}
