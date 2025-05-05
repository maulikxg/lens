package repository

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/netdisco/netdisco/internal/models"
)

// Store represents a simple file-based storage for profiles
type Store struct {
	dataDir     string
	mutex       sync.RWMutex
	credCounter int
	discCounter int
	jobCounter  int
	counterFile string
}

// counterData holds counter values
type counterData struct {
	CredCounter int `json:"cred_counter"`
	DiscCounter int `json:"disc_counter"`
	JobCounter  int `json:"job_counter"`
}

// NewStore creates a new data store
func NewStore(dataDir string) (*Store, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	// Create subdirectories for different data types
	credentialsDir := filepath.Join(dataDir, "credentials")
	discoveryDir := filepath.Join(dataDir, "discovery")
	jobsDir := filepath.Join(dataDir, "jobs")

	for _, dir := range []string{credentialsDir, discoveryDir, jobsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	// Initialize store
	store := &Store{
		dataDir:     dataDir,
		counterFile: filepath.Join(dataDir, "counters.json"),
	}

	// Load counters
	if err := store.loadCounters(); err != nil {
		// If error loading counters, initialize with defaults
		store.credCounter = 1
		store.discCounter = 1
		store.jobCounter = 1
		// Save defaults
		store.saveCounters()
	}

	return store, nil
}

// loadCounters loads counter values from file
func (s *Store) loadCounters() error {
	data, err := os.ReadFile(s.counterFile)
	if err != nil {
		return err
	}

	var counters counterData
	if err := json.Unmarshal(data, &counters); err != nil {
		return err
	}

	s.credCounter = counters.CredCounter
	s.discCounter = counters.DiscCounter
	s.jobCounter = counters.JobCounter
	return nil
}

// saveCounters saves counter values to file
func (s *Store) saveCounters() error {
	counters := counterData{
		CredCounter: s.credCounter,
		DiscCounter: s.discCounter,
		JobCounter:  s.jobCounter,
	}

	data, err := json.MarshalIndent(counters, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.counterFile, data, 0644)
}

// getNextCredID generates the next credential ID
func (s *Store) getNextCredID() string {
	id := strconv.Itoa(s.credCounter)
	s.credCounter++
	s.saveCounters()
	return id
}

// getNextDiscID generates the next discovery profile ID
func (s *Store) getNextDiscID() string {
	id := strconv.Itoa(s.discCounter)
	s.discCounter++
	s.saveCounters()
	return id
}

// getNextJobID generates the next job ID
func (s *Store) getNextJobID() string {
	id := strconv.Itoa(s.jobCounter)
	s.jobCounter++
	s.saveCounters()
	return id
}

// SaveCredentialProfile saves a credential profile to storage
func (s *Store) SaveCredentialProfile(profile *models.CredentialProfile) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Generate ID if not exists
	if profile.ID == "" {
		profile.ID = s.getNextCredID()
		profile.CreatedAt = time.Now()
	}
	profile.UpdatedAt = time.Now()

	// Marshal to JSON
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credential profile: %v", err)
	}

	// Write to file
	filePath := filepath.Join(s.dataDir, "credentials", profile.ID+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write credential profile to file: %v", err)
	}

	return nil
}

// GetCredentialProfile retrieves a credential profile by ID
func (s *Store) GetCredentialProfile(id string) (*models.CredentialProfile, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Read from file
	filePath := filepath.Join(s.dataDir, "credentials", id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential profile: %v", err)
	}

	// Unmarshal JSON
	var profile models.CredentialProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential profile: %v", err)
	}

	return &profile, nil
}

// ListCredentialProfiles retrieves all credential profiles
func (s *Store) ListCredentialProfiles() ([]*models.CredentialProfile, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var profiles []*models.CredentialProfile

	// Read all files in credentials directory
	credentialsDir := filepath.Join(s.dataDir, "credentials")
	files, err := os.ReadDir(credentialsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials directory: %v", err)
	}

	// Read each file and unmarshal the profile
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(credentialsDir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var profile models.CredentialProfile
		if err := json.Unmarshal(data, &profile); err != nil {
			continue
		}

		profiles = append(profiles, &profile)
	}

	return profiles, nil
}

// DeleteCredentialProfile deletes a credential profile by ID
func (s *Store) DeleteCredentialProfile(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Delete file
	filePath := filepath.Join(s.dataDir, "credentials", id+".json")
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete credential profile: %v", err)
	}

	return nil
}

// SaveDiscoveryProfile saves a discovery profile to storage
func (s *Store) SaveDiscoveryProfile(profile *models.DiscoveryProfile) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Generate ID if not exists
	if profile.ID == "" {
		profile.ID = s.getNextDiscID()
		profile.CreatedAt = time.Now()
	}
	profile.UpdatedAt = time.Now()

	// Marshal to JSON
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal discovery profile: %v", err)
	}

	// Write to file
	filePath := filepath.Join(s.dataDir, "discovery", profile.ID+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write discovery profile to file: %v", err)
	}

	return nil
}

// GetDiscoveryProfile retrieves a discovery profile by ID
func (s *Store) GetDiscoveryProfile(id string) (*models.DiscoveryProfile, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Read from file
	filePath := filepath.Join(s.dataDir, "discovery", id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery profile: %v", err)
	}

	// Unmarshal JSON
	var profile models.DiscoveryProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal discovery profile: %v", err)
	}

	return &profile, nil
}

// ListDiscoveryProfiles retrieves all discovery profiles
func (s *Store) ListDiscoveryProfiles() ([]*models.DiscoveryProfile, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var profiles []*models.DiscoveryProfile

	// Read all files in discovery directory
	discoveryDir := filepath.Join(s.dataDir, "discovery")
	files, err := os.ReadDir(discoveryDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery directory: %v", err)
	}

	// Read each file and unmarshal the profile
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(discoveryDir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var profile models.DiscoveryProfile
		if err := json.Unmarshal(data, &profile); err != nil {
			continue
		}

		profiles = append(profiles, &profile)
	}

	return profiles, nil
}

// DeleteDiscoveryProfile deletes a discovery profile by ID
func (s *Store) DeleteDiscoveryProfile(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Delete file
	filePath := filepath.Join(s.dataDir, "discovery", id+".json")
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete discovery profile: %v", err)
	}

	return nil
}

// SaveDiscoveryJob saves a discovery job to storage
func (s *Store) SaveDiscoveryJob(job *models.DiscoveryJob) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Generate ID if not exists
	if job.ID == "" {
		job.ID = s.getNextJobID()
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal discovery job: %v", err)
	}

	// Write to file
	filePath := filepath.Join(s.dataDir, "jobs", job.ID+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write discovery job to file: %v", err)
	}

	return nil
}

// GetDiscoveryJob retrieves a discovery job by ID
func (s *Store) GetDiscoveryJob(id string) (*models.DiscoveryJob, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Read from file
	filePath := filepath.Join(s.dataDir, "jobs", id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery job: %v", err)
	}

	// Unmarshal JSON
	var job models.DiscoveryJob
	if err := json.Unmarshal(data, &job); err != nil {
		return nil, fmt.Errorf("failed to unmarshal discovery job: %v", err)
	}

	return &job, nil
}

// ListDiscoveryJobs retrieves all discovery jobs
func (s *Store) ListDiscoveryJobs() ([]*models.DiscoveryJob, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var jobs []*models.DiscoveryJob

	// Read all files in jobs directory
	jobsDir := filepath.Join(s.dataDir, "jobs")
	files, err := os.ReadDir(jobsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read jobs directory: %v", err)
	}

	// Read each file and unmarshal the job
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(jobsDir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var job models.DiscoveryJob
		if err := json.Unmarshal(data, &job); err != nil {
			continue
		}

		jobs = append(jobs, &job)
	}

	return jobs, nil
} 