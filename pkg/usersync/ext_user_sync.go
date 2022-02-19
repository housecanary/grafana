package usersync

import (
	"net/http"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/web"
)

type ExtUserSyncAPI struct {
	RouteRegister routing.RouteRegister
	Bus           bus.Bus
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
		Role  models.RoleType
	}
	IsGrafanaAdmin *bool // This is a pointer to know if we should sync this or not (nil = ignore sync)
	IsDisabled     bool
}

type SyncExternalUserInfoResponse struct {
	ID int64 `json:"id"`
}

func ProvideService(routeRegister routing.RouteRegister, bus bus.Bus) (*ExtUserSyncAPI, error) {
	s := &ExtUserSyncAPI{
		RouteRegister: routeRegister,
		Bus:           bus,
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

func (es *ExtUserSyncAPI) SyncUser(c *models.ReqContext) response.Response {
	cmd := SyncExternalUserInfoCommand{}
	if err := web.Bind(c.Req, &cmd); err != nil {
		return response.Error(http.StatusBadRequest, "bad external user info", err)
	}

	var allOrgs []*models.OrgDTO
	roleMap := make(map[int64]models.RoleType)
	addToRoleMap := func(orgID int64, role models.RoleType) {
		old, ok := roleMap[orgID]
		if ok {
			if role.Includes(old) {
				roleMap[orgID] = role
			}
		} else {
			roleMap[orgID] = role
		}
	}
	for _, role := range cmd.OrgRoles {
		if role.OrgID == -1 {
			if allOrgs == nil {
				query := &models.SearchOrgsQuery{
					Limit: 1000,
				}
				err := es.Bus.Dispatch(c.Req.Context(), query)
				if err != nil {
					return response.Error(500, err.Error(), err)
				}
				allOrgs = query.Result
			}

			for _, org := range allOrgs {
				addToRoleMap(org.Id, role.Role)
			}
		} else {
			addToRoleMap(role.OrgID, role.Role)
		}
	}
	extUser := &models.ExternalUserInfo{
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

	upsert := &models.UpsertUserCommand{
		ReqContext:    c,
		ExternalUser:  extUser,
		SignupAllowed: true,
	}

	err := es.Bus.Dispatch(c.Req.Context(), upsert)
	if err != nil {
		return response.Error(500, err.Error(), err)
	}

	return response.Respond(200, &SyncExternalUserInfoResponse{
		ID: upsert.Result.Id,
	})
}

func (es *ExtUserSyncAPI) IsDisabled() bool {
	return false
}
