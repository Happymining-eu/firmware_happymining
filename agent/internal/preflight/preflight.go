// Package preflight runs read-only host checks and reports PASS, WARN, FAIL or
// SKIP for each of them against a requirements data file.
//
// Preflight never changes the host: it reads files under /proc, /sys and /etc,
// runs nvidia-smi and timedatectl with fixed arguments, and optionally makes
// two outbound HTTPS probes. It installs nothing and repartitions nothing.
//
// Passing preflight does NOT guarantee that Vast will verify the machine.
package preflight

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/collector"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// Statuses.
const (
	Pass = "PASS"
	Warn = "WARN"
	Fail = "FAIL"
	Skip = "SKIP"
)

// Unverified is the fixed wording for a check whose threshold was not read on
// an official page.
const Unverified = "requirement not verified against Vast documentation"

// Disclaimer is part of every report.
const Disclaimer = "Preflight is advisory. Passing preflight does not guarantee that Vast will verify or list this machine; Vast decides that with its own tests."

// Check is one result line.
type Check struct {
	ID                string `json:"id"`
	Title             string `json:"title"`
	Status            string `json:"status"`
	Detail            string `json:"detail"`
	Remediation       string `json:"remediation"`
	RequirementSource string `json:"requirement_source"`
}

// Report is the full preflight result.
type Report struct {
	SchemaVersion           int            `json:"schema_version"`
	GeneratedAt             string         `json:"generated_at"`
	AgentVersion            string         `json:"agent_version"`
	Overall                 string         `json:"overall"`
	Summary                 map[string]int `json:"summary"`
	Disclaimer              string         `json:"disclaimer"`
	VastStatement           string         `json:"vast_statement"`
	VastStatementSource     string         `json:"vast_statement_source"`
	RequirementsRetrievedOn string         `json:"requirements_retrieved_on"`
	Checks                  []Check        `json:"checks"`
}

// Env is everything preflight touches, so tests can fake all of it.
type Env struct {
	// Root is prepended to every path that is read ("" on a real host).
	Root   string
	Runner execx.Runner
	Statfs collector.StatfsFunc
	// Arch is the Go architecture name of the host (runtime.GOARCH).
	Arch string
	// ProbeAPI checks that the HappyMining API answers; nil skips the check.
	ProbeAPI func(ctx context.Context) (detail string, err error)
	// ProbeHTTPS checks generic outbound HTTPS to a URL; nil skips the check.
	ProbeHTTPS func(ctx context.Context, url string) error
	// Offline skips both network checks.
	Offline bool
	Now     func() time.Time
}

type runner struct {
	env  Env
	req  *Requirements
	out  []Check
	coll *collector.Real
}

func (r *runner) add(c Check) { r.out = append(r.out, c) }

// gate turns a decided status into WARN when the threshold is not verified.
func gate[T any](th Threshold[T], status, detail string) (string, string) {
	if th.Verified {
		return status, detail
	}
	return Warn, Unverified + ". Observed: " + detail
}

// Run executes every check.
func Run(ctx context.Context, env Env, req *Requirements) Report {
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Runner == nil {
		env.Runner = execx.OS{}
	}
	if env.Statfs == nil {
		env.Statfs = collector.OSStatfs
	}
	r := &runner{env: env, req: req}
	r.coll = &collector.Real{Root: env.Root, Runner: env.Runner, Statfs: env.Statfs}

	r.checkOS()
	r.checkArch()
	cpu := r.checkCPUFlags()
	r.checkKernel()
	r.checkVirtualization(cpu)
	gpus := r.checkGPUs(ctx)
	r.checkDriver(gpus)
	r.checkCores(cpu, gpus)
	r.checkRAM(gpus)
	r.checkStorage()
	r.checkNetwork(ctx)
	r.checkTimeSync(ctx)
	r.checkDocker()
	r.checkVast()
	r.checkSecureBoot()
	r.checkNotChecked()

	rep := Report{
		SchemaVersion:           1,
		GeneratedAt:             protocol.FormatTime(env.Now()),
		AgentVersion:            version.Version,
		Summary:                 map[string]int{Pass: 0, Warn: 0, Fail: 0, Skip: 0},
		Disclaimer:              Disclaimer,
		VastStatement:           req.NoGuarantee.Value,
		VastStatementSource:     req.NoGuarantee.Source,
		RequirementsRetrievedOn: req.RetrievedOn,
		Checks:                  r.out,
	}
	for _, c := range r.out {
		rep.Summary[c.Status]++
	}
	switch {
	case rep.Summary[Fail] > 0:
		rep.Overall = Fail
	case rep.Summary[Warn] > 0:
		rep.Overall = Warn
	default:
		rep.Overall = Pass
	}
	return rep
}

// Render writes the human-readable report.
func Render(w io.Writer, rep Report) {
	fmt.Fprintf(w, "HappyMining preflight (agent %s, requirements retrieved %s)\n\n",
		rep.AgentVersion, rep.RequirementsRetrievedOn)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCHECK\tDETAIL")
	for _, c := range rep.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Status, c.Title, c.Detail)
	}
	_ = tw.Flush()
	first := true
	for _, c := range rep.Checks {
		if (c.Status != Fail && c.Status != Warn) || c.Remediation == "" {
			continue
		}
		if first {
			fmt.Fprintln(w, "\nWhat to do:")
			first = false
		}
		fmt.Fprintf(w, "  [%s] %s: %s\n", c.Status, c.Title, c.Remediation)
		if c.RequirementSource != "" {
			fmt.Fprintf(w, "         source: %s\n", c.RequirementSource)
		}
	}
	keys := make([]string, 0, len(rep.Summary))
	for k := range rep.Summary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, rep.Summary[k]))
	}
	fmt.Fprintf(w, "\nOverall: %s (%s)\n", rep.Overall, strings.Join(parts, " "))
	fmt.Fprintf(w, "\n%s\n", rep.Disclaimer)
	if rep.VastStatement != "" {
		fmt.Fprintf(w, "Vast documentation: \"%s\" (%s)\n", rep.VastStatement, rep.VastStatementSource)
	}
}
