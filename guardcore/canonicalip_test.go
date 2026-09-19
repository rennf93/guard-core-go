package guardcore

import "testing"

func TestCanonicalizeIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4"},
		{"[1.2.3.4]", "1.2.3.4"},
		{"[::1]", "::1"},
		{"::1", "::1"},
		{"2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"0:0:0:0:0:0:0:1", "::1"},
		{"::ffff:192.168.1.1", "192.168.1.1"},
		{"[::ffff:10.0.0.5]", "10.0.0.5"},
		{"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
		{"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
		{"fe80:0:0:0:0:0:0:1", "fe80::1"},
		{"not-an-ip", "not-an-ip"},
		{"1.2.3.4.5", "1.2.3.4.5"},
		{"", ""},
		{"999.1.1.1", "999.1.1.1"},
		{"[not-an-ip]", "[not-an-ip]"},
		{"1.2.3.04", "1.2.3.04"},
	}
	for _, c := range cases {
		if got := CanonicalizeIP(c.in); got != c.want {
			t.Errorf("CanonicalizeIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestStripIPBrackets(t *testing.T) {
	if stripIPBrackets("[::1]") != "::1" {
		t.Error("bracket strip failed")
	}
	if stripIPBrackets("::1") != "::1" {
		t.Error("passthrough failed")
	}
	if stripIPBrackets("[1.2.3.4") != "[1.2.3.4" {
		t.Error("partial brackets passthrough failed")
	}
}
