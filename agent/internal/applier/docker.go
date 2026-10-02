package applier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
)

// Command timeouts.
const (
	timeoutDockerQuick = 60 * time.Second
	timeoutComposeUp   = 60 * time.Minute
	timeoutComposeDown = 10 * time.Minute
	timeoutBuild       = 60 * time.Minute
	timeoutSystemctl   = 30 * time.Second
	timeoutMount       = 2 * time.Minute
	timeoutDpkg        = 20 * time.Minute
)

// Argv forms. Each function returns the arguments after DockerPath; the
// only variable parts are validated ids, paths built by the helper from
// those ids, image references from the installed catalog and catalog argv.

// The commands that work on an existing Compose project select it by name
// only (-p hm-<id>, no -f): Compose then reads no Compose file and no env
// file, interpolates nothing, and acts only on the containers labelled with
// that project. `up` alone needs the catalog's Compose file and the env file.

func argvComposeUp(id, envFile, composeFile string) []string {
	return []string{"compose", "-p", projectName(id), "--env-file", envFile, "-f", composeFile, "up", "-d"}
}

// argvComposeDown never has -v (volumes are plugin data) and never --rmi.
func argvComposeDown(id string) []string {
	return []string{"compose", "-p", projectName(id), "down"}
}

func argvComposeStop(id string) []string {
	return []string{"compose", "-p", projectName(id), "stop"}
}

func argvComposeStart(id string) []string {
	return []string{"compose", "-p", projectName(id), "start"}
}

func argvComposeRestart(id string) []string {
	return []string{"compose", "-p", projectName(id), "restart"}
}

// argvComposePs lists the project's containers, stopped ones included, so
// that a crashed container is seen.
func argvComposePs(id string) []string {
	return []string{"compose", "-p", projectName(id), "ps", "--all", "--format", "json"}
}

func argvComposeExec(id, service string, argv []string) []string {
	return append([]string{"compose", "-p", projectName(id), "exec", "-T", service}, argv...)
}

func argvNetworkInspect() []string { return []string{"network", "inspect", NetworkName} }
func argvNetworkCreate() []string  { return []string{"network", "create", NetworkName} }

func argvImageInspect(image string) []string {
	return []string{"image", "inspect", "--format", "{{.Id}}", image}
}

func argvBuild(image, context string) []string {
	return []string{"build", "-t", image, context}
}

// foreignFormat prints, for every running container, its id and the value
// of the HappyMining label (empty for a container HappyMining did not start).
const foreignFormat = `{{.ID}}	{{.Label "` + PluginLabel + `"}}`

func argvRunningContainers() []string {
	return []string{"ps", "--no-trunc", "--format", foreignFormat}
}

func argvVolumeInspect(volume string) []string {
	return []string{"volume", "inspect", "--format", "{{.Mountpoint}}", volume}
}

func argvVolumeRemove(volume string) []string { return []string{"volume", "rm", volume} }

func argvVolumeList(id string) []string {
	return []string{"volume", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + projectName(id)}
}

// reVolumeName is a Docker volume name as Compose makes them for a plugin.
var reVolumeName = regexp.MustCompile(`^hm-[a-z][a-z0-9-]{0,30}_[a-z][a-z0-9_-]{0,30}$`)

// volumeName is the name Compose gives the named volume of a plugin.
func volumeName(id, volume string) string { return projectName(id) + "_" + volume }

// containerInfo is the part of one `docker compose ps --format json` object
// the helper reads. Compose prints one JSON object per line (recent
// versions) or one JSON array (older versions); both are accepted.
type containerInfo struct {
	Name     string `json:"Name"`
	Service  string `json:"Service"`
	State    string `json:"State"`
	Health   string `json:"Health"`
	ExitCode int    `json:"ExitCode"`
}

// parseComposePs decodes the output of argvComposePs.
func parseComposePs(out []byte) ([]containerInfo, error) {
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, nil
	}
	if out[0] == '[' {
		var list []containerInfo
		if err := json.Unmarshal(out, &list); err != nil {
			return nil, fmt.Errorf("unexpected docker compose ps output")
		}
		return list, nil
	}
	var list []containerInfo
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var c containerInfo
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("unexpected docker compose ps output")
		}
		list = append(list, c)
	}
	return list, nil
}

// observedState turns a project's containers into a plugin state.
func observedState(list []containerInfo) (state, detail string) {
	if len(list) == 0 {
		return appliance.PluginStopped, ""
	}
	running, starting, stopped := 0, 0, 0
	var problems []string
	for _, c := range list {
		switch c.State {
		case "running":
			switch c.Health {
			case "unhealthy":
				problems = append(problems, fmt.Sprintf("service %s is unhealthy", clipText(c.Service, 40)))
			case "starting":
				starting++
			default:
				running++
			}
		case "restarting":
			problems = append(problems, fmt.Sprintf("service %s keeps restarting", clipText(c.Service, 40)))
		case "created":
			starting++
		case "exited", "dead":
			if c.ExitCode != 0 {
				problems = append(problems, fmt.Sprintf("service %s exited with code %d", clipText(c.Service, 40), c.ExitCode))
			} else {
				stopped++
			}
		default: // paused, removing, or anything new
			stopped++
		}
	}
	switch {
	case len(problems) > 0:
		return appliance.PluginError, joinDetails(problems, 300)
	case starting > 0:
		return appliance.PluginStarting, ""
	case running > 0 && stopped == 0:
		return appliance.PluginRunning, ""
	case running > 0:
		return appliance.PluginError, "some services are not running"
	}
	return appliance.PluginStopped, ""
}

// docker runs the Docker CLI.
func (e *Env) docker(ctx context.Context, timeout time.Duration, args ...string) cmdResult {
	return e.run(ctx, timeout, DockerPath, args...)
}

// projectState asks Compose for a plugin's containers.
func (e *Env) projectState(ctx context.Context, id string) (state, detail string, err error) {
	res := e.docker(ctx, timeoutDockerQuick, argvComposePs(id)...)
	if !res.ok {
		return "", "", fmt.Errorf("docker compose ps failed: %s", res.describe(nil))
	}
	list, perr := parseComposePs(res.stdout)
	if perr != nil {
		return "", "", perr
	}
	state, detail = observedState(list)
	return state, detail, nil
}

// foreignContainers counts the running containers without the HappyMining
// label. An error means the answer is unknown, which blocks GPU plugins.
//
// This is a guard, not a proof of safety: an absent container proves nothing
// about rentals (a renter's job may be about to start), and a container can
// carry any label its creator chose.
func (e *Env) foreignContainers(ctx context.Context) (int, error) {
	res := e.docker(ctx, timeoutDockerQuick, argvRunningContainers()...)
	if !res.ok {
		return 0, fmt.Errorf("docker ps failed: %s", res.describe(nil))
	}
	n := 0
	// Each line is "<id>\t<label value>"; the value (and so the tab, once
	// white space is trimmed) is missing for a container without the label.
	for _, line := range strings.Split(string(res.stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		id, label, _ := strings.Cut(line, "\t")
		if strings.TrimSpace(id) == "" || strings.ContainsAny(strings.TrimSpace(id), " \t") {
			return 0, fmt.Errorf("unexpected docker ps output")
		}
		if strings.TrimSpace(label) == "" {
			n++
		}
	}
	return n, nil
}

// volumePath locates a plugin volume and accepts it only as a real directory
// below DockerVolumes.
func (e *Env) volumePath(ctx context.Context, id, volume string) (string, bool, error) {
	res := e.docker(ctx, timeoutDockerQuick, argvVolumeInspect(volumeName(id, volume))...)
	if !res.ok {
		// No such volume: the plugin never created it.
		return "", false, nil
	}
	path := strings.TrimSpace(string(res.stdout))
	if strings.ContainsAny(path, "\n\x00") || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		!strings.HasPrefix(path, e.Paths.DockerVolumes+"/") {
		return "", false, fmt.Errorf("volume %s is not under %s", volumeName(id, volume), e.Paths.DockerVolumes)
	}
	if err := checkRealDir(path); err != nil {
		return "", false, fmt.Errorf("volume %s: %v", volumeName(id, volume), err)
	}
	return path, true, nil
}

// checkRealDir refuses a path whose last component is a link or not a
// directory.
func checkRealDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("not a directory (a symbolic link is refused)")
	}
	return nil
}
