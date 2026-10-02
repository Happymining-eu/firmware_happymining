package preflight

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

//go:embed requirements.json
var embeddedRequirements []byte

// Threshold is one requirement value together with where it comes from and
// whether it was actually read on that official page. A check that depends on
// an unverified threshold reports WARN, never PASS or FAIL.
type Threshold[T any] struct {
	Value             T        `json:"value"`
	Source            string   `json:"source"`
	AdditionalSources []string `json:"additional_sources,omitempty"`
	Verified          bool     `json:"verified"`
	Quote             string   `json:"quote,omitempty"`
	Note              string   `json:"note,omitempty"`
}

// OSRelease identifies a distribution release as in /etc/os-release.
type OSRelease struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
}

// NotChecked is a documented requirement that preflight cannot check locally.
type NotChecked struct {
	Requirement string `json:"requirement"`
	Source      string `json:"source"`
}

// Requirements is the data file behind every preflight threshold.
type Requirements struct {
	SchemaVersion           int                    `json:"schema_version"`
	RetrievedOn             string                 `json:"retrieved_on"`
	RetrievalNote           string                 `json:"retrieval_note"`
	NoGuarantee             Threshold[string]      `json:"no_guarantee"`
	OSReleases              Threshold[[]OSRelease] `json:"os_releases"`
	CPUArchitectures        Threshold[[]string]    `json:"cpu_architectures"`
	CPUFlags                Threshold[[]string]    `json:"cpu_flags"`
	PhysicalCoresPerGPU     Threshold[float64]     `json:"physical_cores_per_gpu"`
	RAMToTotalVRAMRatio     Threshold[float64]     `json:"ram_to_total_vram_ratio"`
	MinVRAMPerGPUMiBExcl    Threshold[int64]       `json:"min_vram_per_gpu_mib_exclusive"`
	IdenticalGPUModels      Threshold[bool]        `json:"identical_gpu_models"`
	NvidiaDriverMin         Threshold[string]      `json:"nvidia_driver_min"`
	NvidiaDriverMaxExcl     Threshold[string]      `json:"nvidia_driver_max_exclusive"`
	SecureBootDisabled      Threshold[bool]        `json:"secure_boot_disabled"`
	DockerStorageMinGB      Threshold[int64]       `json:"docker_storage_min_gb"`
	DockerStorageDedicated  Threshold[bool]        `json:"docker_storage_dedicated"`
	RootFreeMinGB           Threshold[int64]       `json:"root_free_min_gb"`
	DockerStorageFS         Threshold[[]string]    `json:"docker_storage_filesystems"`
	DockerPackagesExpected  Threshold[[]string]    `json:"docker_packages_expected"`
	VastDetectionPaths      Threshold[[]string]    `json:"vast_detection_paths"`
	OutboundHTTPSProbes     []string               `json:"outbound_https_probes"`
	NotCheckedByThisVersion []NotChecked           `json:"not_checked"`
}

// ParseRequirements strictly decodes a requirements file.
func ParseRequirements(data []byte) (*Requirements, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Requirements
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("requirements file: %w", err)
	}
	if r.SchemaVersion != 1 {
		return nil, fmt.Errorf("requirements file: unsupported schema_version %d", r.SchemaVersion)
	}
	if len(r.OSReleases.Value) == 0 || len(r.CPUArchitectures.Value) == 0 {
		return nil, errors.New("requirements file: os_releases and cpu_architectures must not be empty")
	}
	if r.NoGuarantee.Value == "" {
		return nil, errors.New("requirements file: no_guarantee must not be empty")
	}
	return &r, nil
}

// EmbeddedRequirements returns the requirements compiled into the binary.
func EmbeddedRequirements() *Requirements {
	r, err := ParseRequirements(embeddedRequirements)
	if err != nil {
		// The embedded file is validated by the test suite; reaching this
		// means the binary was built from a broken tree.
		panic("embedded preflight requirements are invalid: " + err.Error())
	}
	return r
}

// LoadRequirements reads a requirements file from disk (--requirements).
func LoadRequirements(path string) (*Requirements, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 1024*1024 {
		return nil, errors.New("requirements file is larger than 1 MiB")
	}
	return ParseRequirements(data)
}
