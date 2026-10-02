package applier

import (
	"strings"
	"testing"
)

func TestParseMountInfo(t *testing.T) {
	table := strings.Join([]string{
		"22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw",
		// No optional field at all.
		"23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw",
		// Several optional fields, escapes in the mount point and the source.
		`101 22 0:50 / /srv/happymining/nas/pub ro,nosuid,nodev,noexec,relatime shared:9 master:3 - cifs //10.0.0.5/Public\040Share/a/b\040c ro,vers=3.1.1,cache=strict`,
		`102 22 0:51 /sub\134dir /mnt/tab\011and\012newline rw - nfs4 nas:/volume1/back\040up rw,vers=4.2`,
		// A read-only superblock under a read-write mount.
		"103 22 0:52 / /srv/happymining/nas/bk rw,nosuid - nfs host:/export ro,vers=3",
		// Stacked mounts: the last one is the visible one.
		"104 22 0:53 / /srv/happymining/nas/docs rw - tmpfs tmpfs rw",
		"105 104 0:54 / /srv/happymining/nas/docs ro - cifs //nas/docs ro",
		"",
	}, "\n")
	entries, err := ParseMountInfo(strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 7 {
		t.Fatalf("%d entries", len(entries))
	}
	pub, ok := mountAt(entries, "/srv/happymining/nas/pub")
	if !ok || pub.FSType != "cifs" || pub.Source != "//10.0.0.5/Public Share/a/b c" || pub.ReadWrite() || pub.ID != 101 || pub.ParentID != 22 {
		t.Fatalf("pub: %+v", pub)
	}
	odd, ok := mountAt(entries, "/mnt/tab\tand\nnewline")
	if !ok || odd.Root != `/sub\dir` || odd.Source != "nas:/volume1/back up" || !odd.ReadWrite() {
		t.Fatalf("escapes: %+v", odd)
	}
	bk, _ := mountAt(entries, "/srv/happymining/nas/bk")
	if bk.ReadWrite() {
		t.Fatal("a read-only superblock is not writable")
	}
	docs, _ := mountAt(entries, "/srv/happymining/nas/docs")
	if docs.FSType != "cifs" || docs.ID != 105 {
		t.Fatalf("the last mount at a path is the visible one: %+v", docs)
	}
	if _, ok := mountAt(entries, "/srv/happymining/nas"); ok {
		t.Fatal("no mount at the root")
	}
	if !hasOption(pub.SuperOptions, "cache=strict") {
		t.Fatalf("super options: %q", pub.SuperOptions)
	}
}

func TestParseMountInfoRefusesDamagedTables(t *testing.T) {
	for _, bad := range []string{
		"garbage",
		"22 1 8:1 / / rw shared:1 ext4 /dev/sda1 rw",   // no separator
		"x 1 8:1 / / rw - ext4 /dev/sda1 rw",           // bad id
		"22 1 8:1 / /mnt\\04 rw - ext4 /dev/sda1 rw",   // truncated escape
		"22 1 8:1 / /mnt\\999 rw - ext4 /dev/sda1 rw",  // not octal
		"22 1 8:1 / /mnt\\777x rw - ext4 /dev/sda1 rw", // out of range
		"22 1 8:1 / / rw -",
	} {
		if _, err := ParseMountInfo(strings.NewReader(bad + "\n")); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if e, err := ParseMountInfo(strings.NewReader("")); err != nil || len(e) != 0 {
		t.Fatalf("an empty table: %v %v", e, err)
	}
}

func TestReadMountInfoErrorIsNotEmpty(t *testing.T) {
	h := newHarness(t)
	h.env.Paths.MountInfo = h.root + "/missing"
	if _, err := h.env.readMountInfo(); err == nil {
		t.Fatal("an unreadable table must be an error, not 'nothing mounted'")
	}
}
