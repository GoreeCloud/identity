package registration

import "testing"

func TestPolicyDefaultsFailClosedForPublicRegistration(t *testing.T) {
	var policy Policy
	if policy.Allows(Request{Method: MethodPublic}) {
		t.Fatal("zero-value policy unexpectedly allows public registration")
	}
}

func TestPolicyAllowsExplicitAdministratorProvisioning(t *testing.T) {
	var policy Policy
	if !policy.Allows(Request{Method: MethodAdministrator, AdministratorGrant: true}) {
		t.Fatal("administrator-authorized provisioning should be allowed")
	}
}

func TestPolicyAllowsValidInvitation(t *testing.T) {
	var policy Policy
	if !policy.Allows(Request{Method: MethodInvitation, InvitationValid: true}) {
		t.Fatal("valid invitation should be allowed")
	}
}

func TestPolicyAllowsPublicRegistrationOnlyWhenExplicitlyEnabled(t *testing.T) {
	policy := Policy{PublicRegistrationEnabled: true}
	if !policy.Allows(Request{Method: MethodPublic}) {
		t.Fatal("explicitly enabled public registration should be allowed")
	}
}

func TestPolicyRejectsUnknownMethod(t *testing.T) {
	policy := Policy{PublicRegistrationEnabled: true}
	if policy.Allows(Request{Method: Method("unknown")}) {
		t.Fatal("unknown registration method must fail closed")
	}
}
