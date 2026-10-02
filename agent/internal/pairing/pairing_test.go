package pairing

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	const want = "HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA"
	inputs := []string{
		"HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA",
		"hm-7k2m9q-4f8t-zp3d-w6nh-r5xa",
		"HM7K2M9Q4F8TZP3DW6NHR5XA",
		"  hm 7k2m9q 4f8t zp3d w6nh r5xa \n",
		"HM-7K2M-9Q4F-8TZP-3DW6-NHR5-XA",
	}
	for _, in := range inputs {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestNormalizeLookalikes(t *testing.T) {
	// O is read as 0, I and L as 1.
	got, err := Normalize("HM-OIL000-OOOO-IIII-LLLL-oilo")
	if err != nil {
		t.Fatal(err)
	}
	if got != "HM-011000-0000-1111-1111-0110" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeRejects(t *testing.T) {
	bad := []string{
		"",
		"HM",
		"XX-7K2M9Q-4F8T-ZP3D-W6NH-R5XA",  // wrong prefix
		"HM-7K2M9Q-4F8T-ZP3D-W6NH-R5X",   // too short
		"HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XAA", // too long
		"HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XU",  // U is not Crockford base32
		"HM-7K2M9Q-4F8T-ZP3D-W6NH-R5X!",
		"HM-7K2M9Q_4F8T_ZP3D_W6NH_R5XA",
		"HM-7K2M9Q-4F8T-ZP3D-W6NH-R5Xé",
	}
	for _, in := range bad {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q; want an error", in, got)
		} else if len(in) > 8 && strings.Contains(err.Error(), in) {
			t.Errorf("the error must not echo the input: %v", err)
		}
	}
}

func TestMask(t *testing.T) {
	if got := Mask("HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA"); got != "HM-7K2M9Q-****-****-****-****" {
		t.Fatalf("got %q", got)
	}
	if got := Mask("garbage"); strings.Contains(got, "garbage") {
		t.Fatalf("got %q", got)
	}
}
