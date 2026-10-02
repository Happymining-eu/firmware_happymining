package applier

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// SecretSet is `hm-helper secret-set <name>`: read a secret from in (at most
// 4096 bytes; one trailing line end is removed), seal it for this machine's
// own key and store it in local-secrets.json. Only names the local
// profile's document refers to are accepted. The apply unit is started so
// that the secret is used.
func SecretSet(ctx context.Context, e *Env, name string, in io.Reader) error {
	if err := e.check(); err != nil {
		return err
	}
	if !seal.ValidName(name) {
		return seal.ErrName
	}
	cat, err := e.loadCatalog()
	if err != nil {
		return fmt.Errorf("the installed plugin catalog cannot be used: %v", err)
	}
	prof, err := appliance.LoadProfile(e.Paths.ProfilePath, e.OwnerUID, cat)
	if err != nil {
		return err
	}
	if prof.Document == nil {
		return fmt.Errorf("the local profile %s has no document, so it refers to no secret", e.Paths.ProfilePath)
	}
	known := false
	for _, ref := range appliance.SecretRefs(prof.Document, cat) {
		known = known || ref.Name == name
	}
	if !known {
		return fmt.Errorf("%s is not a secret the local profile's document refers to", name)
	}
	buf := make([]byte, seal.MaxPlaintextBytes+3)
	n, err := io.ReadFull(io.LimitReader(in, int64(len(buf))), buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		seal.Wipe(buf)
		return fmt.Errorf("the secret could not be read")
	}
	plain := buf[:n]
	if len(plain) > 0 && plain[len(plain)-1] == '\n' {
		plain = plain[:len(plain)-1]
		if len(plain) > 0 && plain[len(plain)-1] == '\r' {
			plain = plain[:len(plain)-1]
		}
	}
	defer seal.Wipe(buf)
	if len(plain) == 0 || len(plain) > seal.MaxPlaintextBytes {
		return seal.ErrPlaintextSize
	}
	key, err := e.sealKey()
	if err != nil {
		return err
	}
	sealed, err := seal.Seal(key.Public(), name, plain)
	if err != nil {
		return err
	}
	l, err := takeLock(e.Paths.state(stateLockFile))
	if err != nil {
		return err
	}
	secrets, _, err := e.loadLocalSecrets()
	if err != nil {
		l.release()
		return err
	}
	secrets[name] = sealed
	data, err := json.MarshalIndent(secrets, "", " ")
	if err == nil {
		err = writeFile(e.Paths.StateDir, localSecretsFile, append(data, '\n'), 0o600)
	}
	l.release()
	if err != nil {
		return err
	}
	e.audit("secret-set: %s stored (sealed for this machine)", name)
	if e.applyAllowed() {
		e.requestApply(ctx)
	}
	return nil
}

// Purge is `hm-helper appliance-purge <id>`: delete a plugin's data (its
// Compose volumes, its data directory and env file) after checking that it
// is in no document and has no running container, and after the person at
// the terminal typed the id again. It is the only place plugin data is
// deleted.
func Purge(ctx context.Context, e *Env, id string, in io.Reader, prompt io.Writer) error {
	if err := e.check(); err != nil {
		return err
	}
	if !ValidID(id) {
		return fmt.Errorf("not a plugin id")
	}
	if !e.hasDocker() {
		return fmt.Errorf("docker is not installed")
	}
	eff, err := e.resolve()
	if err != nil {
		return err
	}
	if eff.Doc != nil && listed(eff.Doc, id) {
		return fmt.Errorf("plugin %s is in the document in force; remove it from the document first", id)
	}
	if applied, err := e.loadApplied(); err == nil && applied != nil {
		if doc, err := appliance.ParseDocument(applied.Document, eff.Catalog); err == nil && listed(doc, id) {
			return fmt.Errorf("plugin %s is in the stored cloud document; remove it there first", id)
		}
	}
	res := e.docker(ctx, timeoutDockerQuick, argvComposePs(id)...)
	if !res.ok {
		return fmt.Errorf("the containers of plugin %s cannot be listed: %s", id, res.describe(nil))
	}
	list, err := parseComposePs(res.stdout)
	if err != nil {
		return err
	}
	for _, c := range list {
		if c.State != "exited" && c.State != "dead" && c.State != "created" {
			return fmt.Errorf("plugin %s still has a container that is %s; it must be stopped first", id, clipText(c.State, 20))
		}
	}
	fmt.Fprintf(prompt, "This deletes every volume and file of plugin %s. Type %s to confirm: ", id, id)
	line, _ := bufio.NewReaderSize(io.LimitReader(in, 256), 256).ReadString('\n')
	if strings.TrimSpace(line) != id {
		return fmt.Errorf("not confirmed; nothing was deleted")
	}
	if res := e.down(ctx, id); !res.ok {
		return fmt.Errorf("the stopped containers of plugin %s could not be removed: %s", id, res.describe(nil))
	}
	volumes := map[string]bool{}
	if entry, ok := eff.Catalog.Plugin(id); ok {
		for _, v := range entry.Volumes {
			volumes[volumeName(id, v.Name)] = true
		}
	}
	if res := e.docker(ctx, timeoutDockerQuick, argvVolumeList(id)...); res.ok {
		for _, name := range strings.Fields(string(res.stdout)) {
			if strings.HasPrefix(name, projectName(id)+"_") && reVolumeName.MatchString(name) {
				volumes[name] = true
			}
		}
	}
	var problems []string
	for name := range volumes {
		if !strings.HasPrefix(name, projectName(id)+"_") {
			continue
		}
		if res := e.docker(ctx, timeoutDockerQuick, argvVolumeRemove(name)...); !res.ok && !strings.Contains(string(res.stderr), "no such volume") {
			problems = append(problems, "volume "+name+": "+res.describe(nil))
		}
	}
	dataDir := e.Paths.pluginData(id)
	if fi, err := os.Lstat(dataDir); err == nil {
		if !fi.IsDir() {
			problems = append(problems, dataDir+" is not a directory; left alone")
		} else if err := os.RemoveAll(dataDir); err != nil {
			problems = append(problems, "the data directory could not be removed")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		problems = append(problems, "the data directory cannot be examined")
	}
	_ = removeFile(e.Paths.pluginsEnvDir(), id+".env")
	_, _ = e.updateState(func(st *State) { st.dropPlugin(id) })
	e.audit("appliance-purge: data of plugin %s deleted", id)
	if len(problems) > 0 {
		return fmt.Errorf("purge incomplete: %s", strings.Join(problems, "; "))
	}
	return nil
}

func listed(doc *appliance.Document, id string) bool {
	for _, p := range doc.Plugins {
		if p.ID == id {
			return true
		}
	}
	return false
}

// VectorizerToken is `hm-helper vectorizer-token`: create the vectorizer's
// bearer token if it is missing and print it.
func VectorizerToken(e *Env, out io.Writer) error {
	if err := e.check(); err != nil {
		return err
	}
	token, err := e.ensureVectorizerToken()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, token)
	return nil
}
