package api

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	models2 "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/util"
)

func TestCalculateChanges(t *testing.T) {
	orgId := rand.Int63()

	t.Run("detects alerts that need to be added", func(t *testing.T) {
		fakeStore := store.NewFakeRuleStore(t)

		namespace := randFolder()
		groupName := util.GenerateShortUID()
		submitted := models.GenerateAlertRules(rand.Intn(5)+1, models.AlertRuleGen(withOrgID(orgId), simulateSubmitted, withoutUID))

		changes, err := calculateChanges(context.Background(), fakeStore, orgId, namespace, groupName, submitted)
		require.NoError(t, err)

		require.Equal(t, changes.newRules, len(submitted))
		require.Empty(t, changes.Delete)
		require.Len(t, changes.Upsert, len(submitted))
		for _, rule := range changes.Upsert {
			require.Nil(t, rule.Existing)
		}

		opts := []cmp.Option{
			cmp.FilterPath(func(path cmp.Path) bool {
				return path.String() == "Data.modelProps"
			}, cmp.Ignore()),
		}

	outerloop:
		for _, expected := range submitted {
			for _, rule := range changes.Upsert {
				if cmp.Equal(*expected, rule.New, opts...) {
					continue outerloop
				}
			}
			require.Fail(t, "changes did not contain rule that was submitted")
		}
	})

	t.Run("detects alerts that need to be deleted", func(t *testing.T) {
		namespace := randFolder()
		groupName := util.GenerateShortUID()
		inDatabaseMap, inDatabase := models.GenerateUniqueAlertRules(rand.Intn(5)+1, models.AlertRuleGen(withOrgID(orgId), withGroup(groupName), withNamespace(namespace)))

		fakeStore := store.NewFakeRuleStore(t)
		fakeStore.PutRule(context.Background(), inDatabase...)

		changes, err := calculateChanges(context.Background(), fakeStore, orgId, namespace, groupName, make([]*models.AlertRule, 0))
		require.NoError(t, err)

		require.Equal(t, 0, changes.newRules)
		require.Len(t, changes.Upsert, 0)
		require.Len(t, changes.Delete, len(inDatabaseMap))
		for _, toDelete := range changes.Delete {
			require.Contains(t, inDatabaseMap, toDelete.UID)
			db := inDatabaseMap[toDelete.UID]
			require.Equal(t, db, toDelete)
		}
	})

	t.Run("should detect alerts that needs to be updated", func(t *testing.T) {
		namespace := randFolder()
		groupName := util.GenerateShortUID()
		inDatabaseMap, inDatabase := models.GenerateUniqueAlertRules(rand.Intn(5)+1, models.AlertRuleGen(withOrgID(orgId), withGroup(groupName), withNamespace(namespace)))
		submittedMap, submitted := models.GenerateUniqueAlertRules(len(inDatabase), models.AlertRuleGen(withOrgID(orgId), withGroup(groupName), withNamespace(namespace), withUIDs(inDatabaseMap)))

		fakeStore := store.NewFakeRuleStore(t)
		fakeStore.PutRule(context.Background(), inDatabase...)

		changes, err := calculateChanges(context.Background(), fakeStore, orgId, namespace, groupName, submitted)
		require.NoError(t, err)

		require.Len(t, changes.Upsert, len(inDatabase))
		for _, upsert := range changes.Upsert {
			require.NotNil(t, upsert.Existing)
			require.Equal(t, upsert.Existing.UID, upsert.New.UID)
			require.Equal(t, inDatabaseMap[upsert.Existing.UID], upsert.Existing)
			require.Equal(t, *submittedMap[upsert.Existing.UID], upsert.New)
		}
		require.Len(t, changes.Delete, 0)
		require.Equal(t, 0, changes.newRules)
	})

	t.Run("should be able to find alerts by UID in other group/namespace", func(t *testing.T) {
		inDatabaseMap, inDatabase := models.GenerateUniqueAlertRules(rand.Intn(10)+10, models.AlertRuleGen(withOrgID(orgId)))

		fakeStore := store.NewFakeRuleStore(t)
		fakeStore.PutRule(context.Background(), inDatabase...)

		namespace := randFolder()
		groupName := util.GenerateShortUID()
		submittedMap, submitted := models.GenerateUniqueAlertRules(rand.Intn(len(inDatabase)-5)+5, models.AlertRuleGen(withOrgID(orgId), withGroup(groupName), withNamespace(namespace), withUIDs(inDatabaseMap)))

		changes, err := calculateChanges(context.Background(), fakeStore, orgId, namespace, groupName, submitted)
		require.NoError(t, err)

		require.Len(t, changes.Delete, 0)
		require.Equal(t, 0, changes.newRules)
		require.Len(t, changes.Upsert, len(submitted))
		for _, upsert := range changes.Upsert {
			require.NotNil(t, upsert.Existing)
			require.Equal(t, upsert.Existing.UID, upsert.New.UID)
			require.Equal(t, inDatabaseMap[upsert.Existing.UID], upsert.Existing)
			require.Equal(t, *submittedMap[upsert.Existing.UID], upsert.New)
		}
	})

	t.Run("should fail when submitted rule has UID that does not exist in db", func(t *testing.T) {
		fakeStore := store.NewFakeRuleStore(t)

		namespace := randFolder()
		groupName := util.GenerateShortUID()
		submitted := models.AlertRuleGen(withOrgID(orgId), simulateSubmitted)()
		require.NotEqual(t, "", submitted.UID)

		_, err := calculateChanges(context.Background(), fakeStore, orgId, namespace, groupName, []*models.AlertRule{submitted})
		require.Error(t, err)
	})

	t.Run("should fail if cannot fetch current rules in the group", func(t *testing.T) {
		fakeStore := store.NewFakeRuleStore(t)
		expectedErr := errors.New("TEST ERROR")
		fakeStore.Hook = func(cmd interface{}) error {
			switch cmd.(type) {
			case models.ListRuleGroupAlertRulesQuery:
				return expectedErr
			}
			return nil
		}

		namespace := randFolder()
		groupName := util.GenerateShortUID()
		submitted := models.AlertRuleGen(withOrgID(orgId), simulateSubmitted, withoutUID)()

		_, err := calculateChanges(context.Background(), fakeStore, orgId, namespace, groupName, []*models.AlertRule{submitted})
		require.ErrorIs(t, err, expectedErr)
	})

	t.Run("should fail if cannot fetch rule by UID", func(t *testing.T) {
		fakeStore := store.NewFakeRuleStore(t)
		expectedErr := errors.New("TEST ERROR")
		fakeStore.Hook = func(cmd interface{}) error {
			switch cmd.(type) {
			case models.GetAlertRuleByUIDQuery:
				return expectedErr
			}
			return nil
		}

		namespace := randFolder()
		groupName := util.GenerateShortUID()
		submitted := models.AlertRuleGen(withOrgID(orgId), simulateSubmitted)()

		_, err := calculateChanges(context.Background(), fakeStore, orgId, namespace, groupName, []*models.AlertRule{submitted})
		require.Error(t, err, expectedErr)
	})
}

func withOrgID(orgId int64) func(rule *models.AlertRule) {
	return func(rule *models.AlertRule) {
		rule.OrgID = orgId
	}
}

func withGroup(groupName string) func(rule *models.AlertRule) {
	return func(rule *models.AlertRule) {
		rule.RuleGroup = groupName
	}
}

func withNamespace(namespace *models2.Folder) func(rule *models.AlertRule) {
	return func(rule *models.AlertRule) {
		rule.NamespaceUID = namespace.Uid
	}
}

// simulateSubmitted resets some fields of the structure that are not populated by API model to model conversion
func simulateSubmitted(rule *models.AlertRule) {
	rule.ID = 0
	rule.Version = 0
	rule.Updated = time.Time{}
}

func withoutUID(rule *models.AlertRule) {
	rule.UID = ""
}

func withUIDs(uids map[string]*models.AlertRule) func(rule *models.AlertRule) {
	unused := make([]string, 0, len(uids))
	for s := range uids {
		unused = append(unused, s)
	}
	return func(rule *models.AlertRule) {
		if len(unused) == 0 {
			return
		}
		rule.UID = unused[0]
		unused = unused[1:]
	}
}
