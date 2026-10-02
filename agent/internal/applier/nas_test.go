package applier

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
)

func baseDoc(rev int) map[string]any {
	return map[string]any{"schema": 1, "revision": rev, "mode": "private_ai"}
}

func smbEntry(id, host, share, sub, user string, access string) map[string]any {
	e := map[string]any{"id": id, "kind": "smb", "host": host, "share": share, "subpath": sub, "username": user,
		"domain": "", "access": access}
	if user != "" {
		e["secret"] = "nas." + id + ".password"
	}
	return e
}

func nfsEntry(id, host, export, sub, access string) map[string]any {
	e := map[string]any{"id": id, "kind": "nfs", "host": host, "export": export, "access": access}
	if sub != "" {
		e["subpath"] = sub
	}
	return e
}

func TestMountArgvForms(t *testing.T) {
	target, cred := "/T/srv/happymining/nas/x", "/T/state/nas/x.cred"
	cases := []struct {
		name string
		n    appliance.NAS
		want []string
	}{
		{"smb with user", appliance.NAS{ID: "x", Kind: "smb", Host: "nas.lan", Share: "documents", Username: "indexer",
			Secret: "nas.x.password", Access: "read"},
			[]string{"-t", "cifs", "//nas.lan/documents", target, "-o", "ro,nosuid,nodev,noexec,credentials=" + cred}},
		{"smb guest, subpath with spaces", appliance.NAS{ID: "x", Kind: "smb", Host: "10.0.0.5", Share: "Public Share",
			Subpath: "a/b c", Access: "read"},
			[]string{"-t", "cifs", "//10.0.0.5/Public Share/a/b c", target, "-o", "ro,nosuid,nodev,noexec,guest"}},
		{"smb write", appliance.NAS{ID: "x", Kind: "smb", Host: "nas", Share: "bk$", Username: "u", Domain: "CORP",
			Secret: "nas.x.password", Access: "write"},
			[]string{"-t", "cifs", "//nas/bk$", target, "-o", "rw,nosuid,nodev,noexec,credentials=" + cred}},
		{"nfs write", appliance.NAS{ID: "x", Kind: "nfs", Host: "192.168.1.20", Export: "/volume1/backup", Access: "write"},
			[]string{"-t", "nfs", "192.168.1.20:/volume1/backup", target, "-o", "rw,nosuid,nodev,noexec"}},
		{"nfs read with subpath", appliance.NAS{ID: "x", Kind: "nfs", Host: "nas", Export: "/exp/", Subpath: "a/b", Access: "read"},
			[]string{"-t", "nfs", "nas:/exp/a/b", target, "-o", "ro,nosuid,nodev,noexec"}},
		{"nfs root export with subpath", appliance.NAS{ID: "x", Kind: "nfs", Host: "nas", Export: "/", Subpath: "a", Access: "read"},
			[]string{"-t", "nfs", "nas:/a", target, "-o", "ro,nosuid,nodev,noexec"}},
	}
	for _, c := range cases {
		if err := checkNAS(c.n); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if got := argvMount(c.n, target, cred); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestCheckNASRefusesHostileValues(t *testing.T) {
	smb := func(change func(*appliance.NAS)) appliance.NAS {
		n := appliance.NAS{ID: "x", Kind: "smb", Host: "nas", Share: "s", Username: "u", Secret: "nas.x.password", Access: "read"}
		change(&n)
		return n
	}
	nfs := func(change func(*appliance.NAS)) appliance.NAS {
		n := appliance.NAS{ID: "x", Kind: "nfs", Host: "nas", Export: "/e", Access: "read"}
		change(&n)
		return n
	}
	bad := map[string]appliance.NAS{
		"host option":       smb(func(n *appliance.NAS) { n.Host = "-oexec" }),
		"host comma":        smb(func(n *appliance.NAS) { n.Host = "nas,exec" }),
		"host space":        smb(func(n *appliance.NAS) { n.Host = "nas exec" }),
		"host slash":        smb(func(n *appliance.NAS) { n.Host = "nas/x" }),
		"share comma":       smb(func(n *appliance.NAS) { n.Share = "s,uid=0" }),
		"share slash":       smb(func(n *appliance.NAS) { n.Share = "s/../x" }),
		"share trailing":    smb(func(n *appliance.NAS) { n.Share = "s " }),
		"subpath dotdot":    smb(func(n *appliance.NAS) { n.Subpath = "../etc" }),
		"subpath abs":       smb(func(n *appliance.NAS) { n.Subpath = "/etc" }),
		"subpath empty seg": smb(func(n *appliance.NAS) { n.Subpath = "a//b" }),
		"subpath dot":       smb(func(n *appliance.NAS) { n.Subpath = "a/./b" }),
		"subpath newline":   smb(func(n *appliance.NAS) { n.Subpath = "a\nb" }),
		// mount.cifs passes the subpath to the kernel as prefixpath=, unescaped.
		"subpath comma":      smb(func(n *appliance.NAS) { n.Subpath = "docs,file_mode=0777,vers=1.0" }),
		"subpath backslash":  smb(func(n *appliance.NAS) { n.Subpath = "docs\\..\\x" }),
		"nfs subpath comma":  nfs(func(n *appliance.NAS) { n.Subpath = "a,b" }),
		"user comma":         smb(func(n *appliance.NAS) { n.Username = "u,password=x" }),
		"user equals":        smb(func(n *appliance.NAS) { n.Username = "u=x" }),
		"user space":         smb(func(n *appliance.NAS) { n.Username = "u x" }),
		"domain comma":       smb(func(n *appliance.NAS) { n.Domain = "d,sec=none" }),
		"guest with secret":  smb(func(n *appliance.NAS) { n.Username = "" }),
		"user without":       smb(func(n *appliance.NAS) { n.Secret = "" }),
		"wrong secret name":  smb(func(n *appliance.NAS) { n.Secret = "nas.y.password" }),
		"bad access":         smb(func(n *appliance.NAS) { n.Access = "rw" }),
		"bad id":             smb(func(n *appliance.NAS) { n.ID = "../x" }),
		"export dotdot":      nfs(func(n *appliance.NAS) { n.Export = "/a/../b" }),
		"export relative":    nfs(func(n *appliance.NAS) { n.Export = "a" }),
		"export comma":       nfs(func(n *appliance.NAS) { n.Export = "/a,exec" }),
		"export option":      nfs(func(n *appliance.NAS) { n.Export = "/a -o exec" }),
		"unknown kind":       nfs(func(n *appliance.NAS) { n.Kind = "sshfs" }),
		"nfs host option":    nfs(func(n *appliance.NAS) { n.Host = "-o" }),
		"nfs subpath dotdot": nfs(func(n *appliance.NAS) { n.Subpath = "a/.." }),
	}
	for name, n := range bad {
		if err := checkNAS(n); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

// A document that bypassed validation (built directly) still never reaches
// mount with a hostile value.
func TestHostileNASNeverReachesMount(t *testing.T) {
	h := newHarness(t)
	doc := emptyVast()
	doc.Mode = appliance.ModePrivateAI
	doc.NAS = []appliance.NAS{{ID: "x", Kind: "smb", Host: "nas,exec", Share: "s", Access: "read"}}
	out := h.env.applyNAS(context.Background(), doc, h.env.newOpener(nil), nil)
	if len(out.Failed) != 1 || count(h.sys.lines(), MountPath) != 0 {
		t.Fatalf("%+v %q", out, h.sys.lines())
	}
}

func nasDoc(h *harness, rev int, entries ...map[string]any) map[string]any {
	doc := baseDoc(rev)
	doc["nas"] = entries
	secrets := map[string]any{}
	for _, e := range entries {
		if s, ok := e["secret"].(string); ok {
			secrets[s] = ""
		}
	}
	if len(secrets) > 0 {
		doc["secrets"] = secrets
	}
	return h.withSecrets(doc, map[string]string{"nas.docs.password": "p@ss, word=1 $x \"q\""})
}

func TestApplyMountsAndIsIdempotent(t *testing.T) {
	h := newHarness(t)
	docs := smbEntry("docs", "nas.lan", "documents", "", "indexer", "read")
	pub := smbEntry("pub", "10.0.0.5", "Public Share", "a/b c", "", "read")
	bk := nfsEntry("bk", "192.168.1.20", "/volume1/backup", "", "write")
	doc := nasDoc(h, 1, docs, pub, bk)
	if out := h.apply(doc); !out.OK {
		t.Fatalf("%+v", out)
	}
	p := h.env.Paths
	var mounts []string
	for _, l := range h.sys.lines() {
		if strings.HasPrefix(l, MountPath) {
			mounts = append(mounts, l)
		}
	}
	want := []string{
		MountPath + " -t cifs //nas.lan/documents " + p.mountPoint("docs") + " -o ro,nosuid,nodev,noexec,credentials=" + p.credFile("docs"),
		MountPath + " -t cifs //10.0.0.5/Public Share/a/b c " + p.mountPoint("pub") + " -o ro,nosuid,nodev,noexec,guest",
		MountPath + " -t nfs 192.168.1.20:/volume1/backup " + p.mountPoint("bk") + " -o rw,nosuid,nodev,noexec",
	}
	if !reflect.DeepEqual(mounts, want) {
		t.Fatalf("mounts:\n%s", strings.Join(mounts, "\n"))
	}
	cred, err := os.ReadFile(p.credFile("docs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cred) != "username=indexer\npassword=p@ss, word=1 $x \"q\"\n" || mode(t, p.credFile("docs")) != 0o600 {
		t.Fatalf("credentials file %q %o", cred, mode(t, p.credFile("docs")))
	}
	if _, err := os.Lstat(p.credFile("pub")); err == nil {
		t.Fatal("guest access has no credentials file")
	}
	st := h.state()
	if st.ApplyStatus != appliance.ApplyApplied || st.CloudRevision != 1 {
		t.Fatalf("%+v", st)
	}
	for _, id := range []string{"docs", "pub", "bk"} {
		if r, _ := st.findNAS(id); r.State != appliance.NASMounted || !r.Mounted {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	for _, l := range append(h.sys.lines(), h.auditText()) {
		if strings.Contains(l, "p@ss") {
			t.Fatalf("the password reached a command line or the audit: %q", l)
		}
	}
	if mode(t, p.StateDir) != 0o700 || mode(t, p.nasCredDir()) != 0o700 || mode(t, p.mountPoint("docs")) != 0o755 {
		t.Fatal("directory modes")
	}
	assertFixedPrograms(t, h.sys)

	// The same revision again: nothing is restarted.
	h.sys.reset()
	if out := h.apply(doc); !out.OK || out.Detail != "revision already applied" || len(h.sys.lines()) != 0 {
		t.Fatalf("%+v %q", out, h.sys.lines())
	}
	// The same document under a new revision: applied, but nothing is
	// mounted again.
	doc["revision"] = 2
	h.sys.reset()
	if out := h.apply(doc); !out.OK {
		t.Fatalf("%+v", out)
	}
	if n := count(h.sys.lines(), MountPath) + count(h.sys.lines(), UmountPath); n != 0 {
		t.Fatalf("idempotent apply ran mount commands: %q", h.sys.lines())
	}
}

func TestApplyUnmountsRemovedAndRemountsChanged(t *testing.T) {
	h := newHarness(t)
	p := h.env.Paths
	docs := smbEntry("docs", "nas.lan", "documents", "", "indexer", "read")
	bk := nfsEntry("bk", "192.168.1.20", "/volume1/backup", "", "write")
	h.mustApply(nasDoc(h, 1, docs, bk))

	// docs changes its subpath, bk leaves the document.
	docs["subpath"] = "team"
	h.sys.reset()
	h.mustApply(nasDoc(h, 2, docs))
	lines := h.sys.lines()
	iUmountBk := index(lines, UmountPath+" "+p.mountPoint("bk"))
	iUmountDocs := index(lines, UmountPath+" "+p.mountPoint("docs"))
	iMountDocs := index(lines, MountPath+" -t cifs //nas.lan/documents/team ")
	if iUmountBk < 0 || iUmountDocs < 0 || iMountDocs < iUmountDocs {
		t.Fatalf("commands: %q", lines)
	}
	st := h.state()
	if _, ok := st.findNAS("bk"); ok {
		t.Fatal("the removed entry is still recorded")
	}

	// A password change is a remount too.
	h.sys.reset()
	doc := nasDoc(h, 3, docs)
	doc["secrets"].(map[string]any)["nas.docs.password"] = h.sealFor("nas.docs.password", "new")
	h.mustApply(doc)
	if count(h.sys.lines(), UmountPath) != 1 || count(h.sys.lines(), MountPath) != 1 {
		t.Fatalf("a new password must remount: %q", h.sys.lines())
	}
	if c, _ := os.ReadFile(p.credFile("docs")); !strings.Contains(string(c), "password=new\n") {
		t.Fatalf("credentials %q", c)
	}

	// Everything removed: unmounted and the credentials file is gone.
	h.sys.reset()
	h.mustApply(baseDoc(4))
	if count(h.sys.lines(), UmountPath) != 1 {
		t.Fatalf("%q", h.sys.lines())
	}
	if _, err := os.Lstat(p.credFile("docs")); err == nil {
		t.Fatal("the credentials file of a removed entry must be deleted")
	}
}

func TestForeignMountIsNeverTouched(t *testing.T) {
	h := newHarness(t)
	p := h.env.Paths
	// Something else is mounted at the mount point (and at a path below the
	// root that HappyMining never mounted).
	h.writeFile(p.MountInfo, "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"+
		"60 22 0:30 / "+p.mountPoint("docs")+" rw - cifs //other/share rw\n"+
		"61 22 0:31 / "+p.mountPoint("old")+" rw - nfs other:/x rw\n", 0o644)
	h.mustApply(nasDoc(h, 1, smbEntry("docs", "nas.lan", "documents", "", "indexer", "read")))
	if n := count(h.sys.lines(), MountPath) + count(h.sys.lines(), UmountPath); n != 0 {
		t.Fatalf("a mount HappyMining did not make was touched: %q", h.sys.lines())
	}
	st := h.state()
	if r, _ := st.findNAS("docs"); r.State != appliance.NASError || r.Mounted {
		t.Fatalf("%+v", r)
	}
	if st.ApplyStatus != appliance.ApplyPartial {
		t.Fatalf("status %s", st.ApplyStatus)
	}
	// A recorded entry whose mount was replaced by someone else's is not
	// unmounted either when it leaves the document... it is unmounted only
	// when HappyMining mounted it (recorded) and it is a network file system.
	h.sys.reset()
	h.mustApply(baseDoc(2))
	if count(h.sys.lines(), UmountPath) != 0 {
		t.Fatalf("%q", h.sys.lines())
	}
}

func TestRebootRemounts(t *testing.T) {
	h := newHarness(t)
	doc := nasDoc(h, 1, nfsEntry("bk", "nas", "/e", "", "write"))
	h.mustApply(doc)
	// Reboot: a new boot id, nothing mounted.
	h.writeFile(h.env.Paths.BootID, "boot-2\n", 0o644)
	h.writeFile(h.env.Paths.MountInfo, "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n", 0o644)
	h.sys.reset()
	if out := h.apply(doc); !out.OK || out.Detail == "revision already applied" {
		t.Fatalf("after a reboot the same revision must be applied again: %+v", out)
	}
	if count(h.sys.lines(), MountPath) != 1 || count(h.sys.lines(), UmountPath) != 0 {
		t.Fatalf("%q", h.sys.lines())
	}
}

func TestNASSwitchOff(t *testing.T) {
	h := newHarness(t)
	h.env.Switches.AllowNAS = false
	doc := nasDoc(h, 1, nfsEntry("bk", "nas", "/e", "", "write"))
	if out := h.apply(doc); !out.OK {
		t.Fatalf("%+v", out)
	}
	if n := count(h.sys.lines(), MountPath) + count(h.sys.lines(), UmountPath); n != 0 {
		t.Fatalf("%q", h.sys.lines())
	}
	st := h.state()
	if st.ApplyStatus != appliance.ApplyDisabled || !strings.Contains(st.ApplyDetail, "ALLOW_NAS") {
		t.Fatalf("%+v", st)
	}
	if r, _ := st.findNAS("bk"); r.State != appliance.NASUnmounted || !strings.Contains(r.Detail, "ALLOW_NAS") {
		t.Fatalf("%+v", r)
	}
}

func TestNASSecretProblems(t *testing.T) {
	for name, tc := range map[string]struct {
		plain  string
		sealed func(h *harness) string
		want   string
	}{
		"newline in password": {plain: "a\nb", want: "line break"},
		"missing secret":      {sealed: func(*harness) string { return "" }, want: "missing"},
		"sealed for another machine": {sealed: func(h *harness) string {
			other := newHarness(h.t)
			return other.sealFor("nas.docs.password", "x")
		}, want: "unreadable"},
		"sealed under another name": {sealed: func(h *harness) string { return h.sealFor("nas.other.password", "x") }, want: "unreadable"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			plain := tc.plain
			if plain == "" {
				plain = "x"
			}
			doc := baseDoc(1)
			doc["nas"] = []map[string]any{smbEntry("docs", "nas.lan", "documents", "", "indexer", "read")}
			doc["secrets"] = map[string]any{"nas.docs.password": h.sealFor("nas.docs.password", plain)}
			if tc.sealed != nil {
				v := tc.sealed(h)
				if v == "" {
					delete(doc, "secrets")
				} else {
					doc["secrets"] = map[string]any{"nas.docs.password": v}
				}
			}
			out := QuickApply(context.Background(), h.env, mustJSON(t, doc))
			if !out.OK {
				// A missing secret is refused by the document rules already.
				if tc.want == "missing" && out.Code == CodeInvalid {
					return
				}
				t.Fatalf("%+v", out)
			}
			if err := ApplyStored(context.Background(), h.env); err != nil {
				t.Fatal(err)
			}
			if count(h.sys.lines(), MountPath) != 0 {
				t.Fatalf("mount ran: %q", h.sys.lines())
			}
			r, _ := h.state().findNAS("docs")
			if r.State != appliance.NASError || !strings.Contains(r.Detail, tc.want) {
				t.Fatalf("%+v", r)
			}
			if _, err := os.Lstat(filepath.Join(h.env.Paths.nasCredDir(), "docs.cred")); err == nil {
				t.Fatal("no credentials file may be left")
			}
		})
	}
}

func TestNASStatesFromMountTable(t *testing.T) {
	h := newHarness(t)
	p := h.env.Paths
	doc := emptyVast()
	doc.NAS = []appliance.NAS{{ID: "a", Kind: "nfs", Host: "h", Export: "/e", Access: "read"},
		{ID: "b", Kind: "nfs", Host: "h", Export: "/e", Access: "read"}, {ID: "c", Kind: "nfs", Host: "h", Export: "/e", Access: "read"}}
	st := newState()
	st.NAS = []NASRecord{{ID: "b", State: appliance.NASError, Detail: "mount failed: exit status 32"}, {ID: "c", State: appliance.NASMounted, Mounted: true}}
	mounts, _ := ParseMountInfo(strings.NewReader("70 22 0:40 / " + escapeMount(p.mountPoint("a")) + " rw - nfs h:/e rw\n"))
	got := nasStates(doc, st, mounts, nil, p)
	want := []appliance.NASState{
		{ID: "a", State: "mounted", Detail: "mounted read-write although the entry is read-only"},
		{ID: "b", State: "error", Detail: "mount failed: exit status 32"},
		{ID: "c", State: "unmounted", Detail: "no longer mounted"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}
