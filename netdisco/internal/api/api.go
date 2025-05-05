package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/netdisco/netdisco/internal/discovery"
	"github.com/netdisco/netdisco/internal/models"
	"github.com/netdisco/netdisco/internal/repository"
)

// API represents the API server
type API struct {
	store    *repository.Store
	router   *mux.Router
	jobMutex sync.Mutex
	jobMap   map[string]*jobContext
	logger   *log.Logger
	dataDir  string
}

type jobContext struct {
	job      *models.DiscoveryJob
	cancelCh chan struct{}
}

// NewAPI creates a new API server
func NewAPI(dataDir string, logger *log.Logger) (*API, error) {
	// Create data directory if not exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	// Create store
	store, err := repository.NewStore(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %v", err)
	}

	// Create router
	router := mux.NewRouter()

	// Create API
	api := &API{
		store:    store,
		router:   router,
		jobMap:   make(map[string]*jobContext),
		logger:   logger,
		dataDir:  dataDir,
	}

	// Register routes
	api.registerRoutes()

	return api, nil
}

// registerRoutes registers API routes
func (api *API) registerRoutes() {
	// Credential profile routes
	api.router.HandleFunc("/api/credentials", api.listCredentialProfiles).Methods("GET")
	api.router.HandleFunc("/api/credentials", api.createCredentialProfile).Methods("POST")
	api.router.HandleFunc("/api/credentials/{id}", api.getCredentialProfile).Methods("GET")
	api.router.HandleFunc("/api/credentials/{id}", api.updateCredentialProfile).Methods("PUT")
	api.router.HandleFunc("/api/credentials/{id}", api.deleteCredentialProfile).Methods("DELETE")

	// Discovery profile routes
	api.router.HandleFunc("/api/discovery", api.listDiscoveryProfiles).Methods("GET")
	api.router.HandleFunc("/api/discovery", api.createDiscoveryProfile).Methods("POST")
	api.router.HandleFunc("/api/discovery/{id}", api.getDiscoveryProfile).Methods("GET")
	api.router.HandleFunc("/api/discovery/{id}", api.updateDiscoveryProfile).Methods("PUT")
	api.router.HandleFunc("/api/discovery/{id}", api.deleteDiscoveryProfile).Methods("DELETE")
	api.router.HandleFunc("/api/discovery/{id}/run", api.runDiscovery).Methods("POST")

	// Discovery job routes
	api.router.HandleFunc("/api/jobs", api.listDiscoveryJobs).Methods("GET")
	api.router.HandleFunc("/api/jobs/{id}", api.getDiscoveryJob).Methods("GET")
	api.router.HandleFunc("/api/jobs/{id}/cancel", api.cancelDiscoveryJob).Methods("POST")
}

// GetRouter returns the API router
func (api *API) GetRouter() *mux.Router {
	return api.router
}

// Credential Profile Handlers

// listCredentialProfiles handles GET /api/credentials
func (api *API) listCredentialProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := api.store.ListCredentialProfiles()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list credential profiles: %v", err), http.StatusInternalServerError)
		return
	}

	respondJSON(w, profiles)
}

// createCredentialProfile handles POST /api/credentials
func (api *API) createCredentialProfile(w http.ResponseWriter, r *http.Request) {
	var profile models.CredentialProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := api.store.SaveCredentialProfile(&profile); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save credential profile: %v", err), http.StatusInternalServerError)
		return
	}

	respondJSON(w, profile)
}

// getCredentialProfile handles GET /api/credentials/{id}
func (api *API) getCredentialProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	profile, err := api.store.GetCredentialProfile(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get credential profile: %v", err), http.StatusNotFound)
		return
	}

	respondJSON(w, profile)
}

// updateCredentialProfile handles PUT /api/credentials/{id}
func (api *API) updateCredentialProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Check if profile exists
	_, err := api.store.GetCredentialProfile(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Credential profile not found: %v", err), http.StatusNotFound)
		return
	}

	var profile models.CredentialProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request body: %v", err), http.StatusBadRequest)
		return
	}

	// Ensure ID is maintained
	profile.ID = id

	if err := api.store.SaveCredentialProfile(&profile); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update credential profile: %v", err), http.StatusInternalServerError)
		return
	}

	respondJSON(w, profile)
}

// deleteCredentialProfile handles DELETE /api/credentials/{id}
func (api *API) deleteCredentialProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := api.store.DeleteCredentialProfile(id); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete credential profile: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Discovery Profile Handlers

// listDiscoveryProfiles handles GET /api/discovery
func (api *API) listDiscoveryProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := api.store.ListDiscoveryProfiles()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list discovery profiles: %v", err), http.StatusInternalServerError)
		return
	}

	respondJSON(w, profiles)
}

// createDiscoveryProfile handles POST /api/discovery
func (api *API) createDiscoveryProfile(w http.ResponseWriter, r *http.Request) {
	var profile models.DiscoveryProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request body: %v", err), http.StatusBadRequest)
		return
	}

	// Set default values if not provided
	if profile.Concurrency == 0 {
		profile.Concurrency = 10
	}
	if profile.Timeout == 0 {
		profile.Timeout = 5
	}

	if err := api.store.SaveDiscoveryProfile(&profile); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save discovery profile: %v", err), http.StatusInternalServerError)
		return
	}

	respondJSON(w, profile)
}

// getDiscoveryProfile handles GET /api/discovery/{id}
func (api *API) getDiscoveryProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	profile, err := api.store.GetDiscoveryProfile(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get discovery profile: %v", err), http.StatusNotFound)
		return
	}

	respondJSON(w, profile)
}

// updateDiscoveryProfile handles PUT /api/discovery/{id}
func (api *API) updateDiscoveryProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Check if profile exists
	_, err := api.store.GetDiscoveryProfile(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Discovery profile not found: %v", err), http.StatusNotFound)
		return
	}

	var profile models.DiscoveryProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request body: %v", err), http.StatusBadRequest)
		return
	}

	// Ensure ID is maintained
	profile.ID = id

	if err := api.store.SaveDiscoveryProfile(&profile); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update discovery profile: %v", err), http.StatusInternalServerError)
		return
	}

	respondJSON(w, profile)
}

// deleteDiscoveryProfile handles DELETE /api/discovery/{id}
func (api *API) deleteDiscoveryProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := api.store.DeleteDiscoveryProfile(id); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete discovery profile: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// runDiscovery handles POST /api/discovery/{id}/run
func (api *API) runDiscovery(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Get discovery profile
	profile, err := api.store.GetDiscoveryProfile(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get discovery profile: %v", err), http.StatusNotFound)
		return
	}

	// Create a new discovery job
	job := &models.DiscoveryJob{
		ID:        "",
		ProfileID: profile.ID,
		Status:    models.DiscoveryStatusPending,
		StartedAt: time.Now(),
	}

	if err := api.store.SaveDiscoveryJob(job); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create discovery job: %v", err), http.StatusInternalServerError)
		return
	}

	// Run discovery in background
	go api.runDiscoveryJob(job, profile)

	respondJSON(w, job)
}

// runDiscoveryJob runs a discovery job in the background
func (api *API) runDiscoveryJob(job *models.DiscoveryJob, profile *models.DiscoveryProfile) {
	// Update job status to running
	job.Status = models.DiscoveryStatusRunning
	api.store.SaveDiscoveryJob(job)

	// Create cancel channel
	cancelCh := make(chan struct{})

	// Store job context
	api.jobMutex.Lock()
	api.jobMap[job.ID] = &jobContext{
		job:      job,
		cancelCh: cancelCh,
	}
	api.jobMutex.Unlock()

	// Create output directory for this job
	jobOutputDir := filepath.Join(api.dataDir, "jobs", job.ID)
	if err := os.MkdirAll(jobOutputDir, 0755); err != nil {
		api.logger.Printf("Failed to create job output directory: %v", err)
		job.Status = models.DiscoveryStatusFailed
		job.ErrorMessage = fmt.Sprintf("Failed to create job output directory: %v", err)
		api.store.SaveDiscoveryJob(job)
		return
	}

	// Get credential profiles
	var credentials []*models.CredentialProfile
	for _, credID := range profile.CredentialIDs {
		cred, err := api.store.GetCredentialProfile(credID)
		if err != nil {
			api.logger.Printf("Failed to get credential profile %s: %v", credID, err)
			continue
		}
		credentials = append(credentials, cred)
	}

	if len(credentials) == 0 {
		job.Status = models.DiscoveryStatusFailed
		job.ErrorMessage = "No valid credential profiles found"
		api.store.SaveDiscoveryJob(job)
		return
	}

	// Create logger for this job
	logFile, err := os.Create(filepath.Join(jobOutputDir, "discovery.log"))
	if err != nil {
		api.logger.Printf("Failed to create job log file: %v", err)
		job.Status = models.DiscoveryStatusFailed
		job.ErrorMessage = fmt.Sprintf("Failed to create job log file: %v", err)
		api.store.SaveDiscoveryJob(job)
		return
	}
	defer logFile.Close()

	jobLogger := log.New(logFile, "", log.LstdFlags)

	// Create discovery config
	config := profile.CreateConfig(credentials, jobOutputDir)

	// Run discovery
	jobLogger.Printf("Starting discovery with target: %s", config.Target)
	devices, err := discovery.Discover(config, jobLogger)
	if err != nil {
		api.logger.Printf("Discovery failed: %v", err)
		job.Status = models.DiscoveryStatusFailed
		job.ErrorMessage = fmt.Sprintf("Discovery failed: %v", err)
		api.store.SaveDiscoveryJob(job)
		return
	}

	// Update last run time
	now := time.Now()
	profile.LastRunAt = &now
	api.store.SaveDiscoveryProfile(profile)

	// Update job with results
	job.Status = models.DiscoveryStatusCompleted
	job.Results = devices
	job.TargetsTotal = len(devices)
	job.TargetsCompleted = len(devices)
	job.TargetsSuccessful = countSuccessfulDevices(devices)
	job.TargetsFailed = job.TargetsTotal - job.TargetsSuccessful
	completedAt := time.Now()
	job.CompletedAt = &completedAt
	api.store.SaveDiscoveryJob(job)

	// Remove job context
	api.jobMutex.Lock()
	delete(api.jobMap, job.ID)
	api.jobMutex.Unlock()
}

// countSuccessfulDevices counts the number of devices with successful scans
func countSuccessfulDevices(devices []models.Device) int {
	count := 0
	for _, device := range devices {
		if device.Reachable && len(device.ScanErrors) == 0 {
			count++
		}
	}
	return count
}

// Discovery Job Handlers

// listDiscoveryJobs handles GET /api/jobs
func (api *API) listDiscoveryJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := api.store.ListDiscoveryJobs()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list discovery jobs: %v", err), http.StatusInternalServerError)
		return
	}

	respondJSON(w, jobs)
}

// getDiscoveryJob handles GET /api/jobs/{id}
func (api *API) getDiscoveryJob(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	job, err := api.store.GetDiscoveryJob(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get discovery job: %v", err), http.StatusNotFound)
		return
	}

	respondJSON(w, job)
}

// cancelDiscoveryJob handles POST /api/jobs/{id}/cancel
func (api *API) cancelDiscoveryJob(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	api.jobMutex.Lock()
	ctx, exists := api.jobMap[id]
	api.jobMutex.Unlock()

	if !exists {
		http.Error(w, "Job not found or already completed", http.StatusNotFound)
		return
	}

	// Send cancel signal
	close(ctx.cancelCh)

	// Update job status
	job, err := api.store.GetDiscoveryJob(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get discovery job: %v", err), http.StatusInternalServerError)
		return
	}

	job.Status = models.DiscoveryStatusFailed
	job.ErrorMessage = "Job was canceled by user"
	completedAt := time.Now()
	job.CompletedAt = &completedAt
	api.store.SaveDiscoveryJob(job)

	respondJSON(w, job)
}

// Utility functions

// respondJSON sends a JSON response
func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
} 