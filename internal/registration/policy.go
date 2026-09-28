package registration

type Method string

const (
	MethodAdministrator Method = "administrator"
	MethodInvitation    Method = "invitation"
	MethodPublic        Method = "public"
)

type Policy struct {
	PublicRegistrationEnabled bool
}

type Request struct {
	Method             Method
	AdministratorGrant bool
	InvitationValid    bool
}

func (p Policy) Allows(request Request) bool {
	switch request.Method {
	case MethodAdministrator:
		return request.AdministratorGrant
	case MethodInvitation:
		return request.InvitationValid
	case MethodPublic:
		return p.PublicRegistrationEnabled
	default:
		return false
	}
}
