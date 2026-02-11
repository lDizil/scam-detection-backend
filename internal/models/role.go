package models

type Role string

const (
	RoleUser      Role = "user"
	RoleModerator Role = "moderator"
	RoleAdmin     Role = "admin"
)

func (r Role) IsValid() bool {
	switch r {
	case RoleUser, RoleModerator, RoleAdmin:
		return true
	}
	return false
}

func GetAllRoles() []Role {
	return []Role{RoleUser, RoleModerator, RoleAdmin}
}
