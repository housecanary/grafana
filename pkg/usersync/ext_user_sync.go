package usersync

import (
	"net/http"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/models/roletype"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/web"
)

type ExtUserSyncAPI struct {
	RouteRegister routing.RouteRegister
	LoginService  login.Service
	OrgService    org.Service
}

type SyncExternalUserInfoCommand struct {
	AuthModule string
	AuthId     string
	Email      string
	Login      string
	Name       string
	Groups     []string
	OrgRoles   []struct {
		OrgID int64
		Role  roletype.RoleType
	}
	IsGrafanaAdmin *bool // This is a pointer to know if we should sync this or not (nil = ignore sync)
	IsDisabled     bool
}

type SyncExternalUserInfoResponse struct {
	ID int64 `json:"id"`
}

func ProvideService(routeRegister routing.RouteRegister, loginService login.Service, orgService org.Service) (*ExtUserSyncAPI, error) {
	s := &ExtUserSyncAPI{
		RouteRegister: routeRegister,
		LoginService:  loginService,
		OrgService:    orgService,
	}
	if s.IsDisabled() {
		return s, nil
	}
	if err := s.init(); err != nil {
		return nil, err
	}

	return s, nil
}

func (es *ExtUserSyncAPI) init() error {
	es.registerRoutes()
	return nil
}

func (es *ExtUserSyncAPI) registerRoutes() {
	reqGrafanaAdmin := middleware.ReqGrafanaAdmin
	wrap := routing.Wrap

	r := es.RouteRegister

	r.Post("/apiext/users/sync", reqGrafanaAdmin, wrap(es.SyncUser))
}

func (es *ExtUserSyncAPI) SyncUser(c *contextmodel.ReqContext) response.Response {
	cmd := SyncExternalUserInfoCommand{}
	if err := web.Bind(c.Req, &cmd); err != nil {
		return response.Error(http.StatusBadRequest, "bad external user info", err)
	}

	var allOrgs []*org.OrgDTO
	roleMap := make(map[int64]roletype.RoleType)
	addToRoleMap := func(orgID int64, role roletype.RoleType) {
		old, ok := roleMap[orgID]
		if ok {
			if role.Includes(old) {
				roleMap[orgID] = role
			}
		} else {
			roleMap[orgID] = role
		}
	}
	var err error
	for _, role := range cmd.OrgRoles {
		if role.OrgID == -1 {
			if allOrgs == nil {
				query := &org.SearchOrgsQuery{
					Limit: 1000,
				}
				allOrgs, err = es.OrgService.Search(c.Req.Context(), query)
				if err != nil {
					return response.Error(500, err.Error(), err)
				}
			}

			for _, orgDTO := range allOrgs {
				addToRoleMap(orgDTO.ID, role.Role)
			}
		} else {
			addToRoleMap(role.OrgID, role.Role)
		}
	}
	extUser := &login.ExternalUserInfo{
		AuthModule:     cmd.AuthModule,
		AuthId:         cmd.AuthId,
		Email:          cmd.Email,
		Login:          cmd.Login,
		Name:           cmd.Name,
		Groups:         cmd.Groups,
		OrgRoles:       roleMap,
		IsGrafanaAdmin: cmd.IsGrafanaAdmin,
		IsDisabled:     cmd.IsDisabled,
	}

	upsert := &login.UpsertUserCommand{
		ReqContext:       c,
		ExternalUser:     extUser,
		SignupAllowed:    true,
		UserLookupParams: login.UserLookupParams{Email: &cmd.Email},
	}

	user, err := es.LoginService.UpsertUser(c.Req.Context(), upsert)
	if err != nil {
		return response.Error(500, err.Error(), err)
	}

	return response.Respond(200, &SyncExternalUserInfoResponse{
		ID: user.ID,
	})
}

func (es *ExtUserSyncAPI) IsDisabled() bool {
	return false
}
