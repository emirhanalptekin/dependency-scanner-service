package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

type Scan struct {
	ID          uuid.UUID  `json:"id"`
	Target      string     `json:"target"`
	ScanID      string     `json:"scan_id"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

type ScanResult struct {
	ID              uuid.UUID `json:"id"`
	ScanID          uuid.UUID `json:"scan_id"`
	VulnerabilityID string    `json:"vulnerability_id"`
	Severity        string    `json:"severity"`
	Description     string    `json:"description"`
	Component       string    `json:"component"`
	CreatedAt       time.Time `json:"created_at"`
}

type StartScanRequest struct {
	Target string `json:"target"`
}

var db *sql.DB

func init() {
	var err error
	connStr := "postgres://postgres:postgres@192.168.0.9:5432/dependency_check?sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
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

	go func() {
		cmd := exec.Command("dependency-check.sh", "--project", scan.Target, "--scan", req.Target, "--format", "JSON", "--out", "scan-result.json")

		var outb, errb bytes.Buffer
		cmd.Stdout = &outb
		cmd.Stderr = &errb

		if err := cmd.Start(); err != nil {
			log.Printf("Error starting scan: %v", err)
			updateScanStatus(scan.ID, "FAILED")
			return
		}

		updateScanStatus(scan.ID, "IN_PROGRESS")

		if err := cmd.Wait(); err != nil {

			fmt.Println("out:", outb.String(), "err:", errb.String())

			log.Printf("Error completing scan: %v", err)
			updateScanStatus(scan.ID, "FAILED")
			return
		}

		updateScanStatus(scan.ID, "COMPLETED")
	}()

	_, err := db.Exec(`
        INSERT INTO scans (id, target, scan_id, status, created_at)
        VALUES ($1, $2, $3, $4, $5)
    `, scan.ID, scan.Target, scan.ScanID, scan.Status, scan.CreatedAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(scan)
}

func getScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scanID"]

	var scan Scan
	var completedAt sql.NullTime

	err := db.QueryRow(`
        SELECT id, target, scan_id, status, created_at, completed_at
        FROM scans WHERE scan_id = $1
    `, scanID).Scan(&scan.ID, &scan.Target, &scan.ScanID, &scan.Status, &scan.CreatedAt, &completedAt)
	if err != nil {
		log.Printf("%v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}
	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}

	json.NewEncoder(w).Encode(scan)
}

func saveScanResults(w http.ResponseWriter, r *http.Request) {
	results := []ScanResult{}
	// implement save mechanism

	for _, result := range results {
		_, err := db.Exec(`
            INSERT INTO scan_results (id, scan_id, vulnerability_id, severity, description, component, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, uuid.New(), result.ScanID, result.VulnerabilityID, result.Severity, result.Description, result.Component, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)
}

func getScanResults(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
        SELECT id, scan_id, vulnerability_id, severity, description, component, created_at
        FROM scan_results
    `)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []ScanResult
	for rows.Next() {
		var result ScanResult
		err := rows.Scan(&result.ID, &result.ScanID, &result.VulnerabilityID, &result.Severity, &result.Description, &result.Component, &result.CreatedAt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		results = append(results, result)
	}

	json.NewEncoder(w).Encode(results)
}

func updateScanStatus(scanID uuid.UUID, status string) {
	_, err := db.Exec(`
        UPDATE scans SET status = $1, completed_at = $2
        WHERE id = $3 AND status != 'COMPLETED'
    `, status, time.Now(), scanID)
	if err != nil {
		log.Printf("Error updating scan status: %v", err)
	}
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/api/scan/start", startScan).Methods("POST")
	router.HandleFunc("/api/scan/status/{scanID}", getScanStatus).Methods("GET")
	router.HandleFunc("/api/scan/save", saveScanResults).Methods("POST")
	router.HandleFunc("/api/scan/results", getScanResults).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", router))
}
