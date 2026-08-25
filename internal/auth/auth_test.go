package auth

import "testing"

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword(h, "wrong password") {
		t.Fatal("wrong password accepted")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestMalformedHashesNeverVerifyOrPanic(t *testing.T) {
	cases := []string{"", "$argon2id$v=19$m=0,t=0,p=0$$", "$argon2id$v=19$m=1,t=1,p=1$YQ$YQ", "$argon2id$v=18$m=65536,t=3,p=2$abc$def", "$argon2id$v=19$m=65536,t=3,p=2junk$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA", "$argon2id$v=19$m=9999999,t=3,p=2$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA"}
	for _, value := range cases {
		if VerifyPassword(value, "anything") {
			t.Fatalf("accepted %q", value)
		}
	}
}

func FuzzVerifyPasswordDoesNotPanic(f *testing.F) {
	f.Add("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY", "password")
	f.Add("garbage", "")
	f.Fuzz(func(t *testing.T, encoded, password string) { _ = VerifyPassword(encoded, password) })
}
