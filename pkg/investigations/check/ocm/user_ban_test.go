package ocm

import (
	"errors"
	"testing"
)

func TestUserBannedError_Error(t *testing.T) {
	err := &UserBannedError{
		UserID:         "user123",
		BanCode:        "FRAUD",
		BanDescription: "Fraudulent activity detected",
	}

	expected := "user user123 is banned: FRAUD - Fraudulent activity detected"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestUserBanCheck_Name(t *testing.T) {
	check := NewUserBanCheck()
	if check.Name() != "ocm_user_ban" {
		t.Errorf("Expected name 'ocm_user_ban', got '%s'", check.Name())
	}
}

func TestUserBannedError_TypeAssertion(t *testing.T) {
	var bannedErr *UserBannedError
	err := &UserBannedError{
		UserID:         "test",
		BanCode:        "TEST",
		BanDescription: "Test ban",
	}

	if !errors.As(err, &bannedErr) {
		t.Error("errors.As should work with UserBannedError")
	}

	if bannedErr.UserID != "test" {
		t.Errorf("Expected UserID 'test', got '%s'", bannedErr.UserID)
	}
}
