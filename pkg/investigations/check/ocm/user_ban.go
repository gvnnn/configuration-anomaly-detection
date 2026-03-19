package ocm

import (
	"errors"
	"fmt"

	amv1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	sdk "github.com/openshift-online/ocm-sdk-go"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/check"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
)

// UserBanCheck validates that the cluster owner is not banned
type UserBanCheck struct{}

// NewUserBanCheck creates a new user ban check instance
func NewUserBanCheck() check.Check {
	return &UserBanCheck{}
}

func (c *UserBanCheck) Name() string {
	return "ocm_user_ban"
}

func (c *UserBanCheck) AppendToNotes(notes *notewriter.NoteWriter, passed bool, err error) {
	if err != nil {
		// Check for typed error (user banned)
		var bannedErr *UserBannedError
		if errors.As(err, &bannedErr) {
			notes.AppendWarning("[%s] User is banned: %s\nBan description: %s\nPlease open a proactive case, so that MCS can resolve the ban or organize a ownership transfer.",
				c.Name(), bannedErr.BanCode, bannedErr.BanDescription)
			return
		}
		// Infrastructure error
		notes.AppendWarning("[%s] Failed to check user ban status: %v", c.Name(), err)
		return
	}

	if passed {
		notes.AppendSuccess("[%s] User is not banned", c.Name())
	}
}

func (c *UserBanCheck) Run(resources *investigation.Resources) (bool, error) {
	if resources.Cluster == nil {
		return false, fmt.Errorf("cluster resource is required")
	}

	// Get cluster creator
	user, err := getCreatorFromCluster(resources.OcmClient.GetConnection(), resources.Cluster)
	if err != nil {
		// Infrastructure error - OCM API failure
		return false, fmt.Errorf("failed to get cluster creator: %w", err)
	}

	// Check if user is banned
	if user.Banned() {
		return false, &UserBannedError{
			UserID:         user.ID(),
			BanCode:        user.BanCode(),
			BanDescription: user.BanDescription(),
		}
	}

	return true, nil // Check passed - user not banned
}

// getCreatorFromCluster retrieves the cluster creator from OCM
// This is moved from pkg/ocm/ocm.go to keep the check self-contained
func getCreatorFromCluster(ocmConn *sdk.Connection, cluster *cmv1.Cluster) (*amv1.Account, error) {
	// Get subscription from cluster
	cmv1Subscription, ok := cluster.GetSubscription()
	if !ok {
		return nil, fmt.Errorf("failed to get subscription from cluster: %s", cluster.ID())
	}

	// Get subscription details
	subscriptionResponse, err := ocmConn.AccountsMgmt().V1().Subscriptions().Subscription(cmv1Subscription.ID()).Get().Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}

	subscription, ok := subscriptionResponse.GetBody()
	if !ok {
		return nil, fmt.Errorf("failed to get subscription body")
	}

	// Verify subscription is active
	if status := subscription.Status(); status != "Active" {
		return nil, fmt.Errorf("expecting status 'Active' found %v", status)
	}

	// Get creator account
	accountResponse, err := ocmConn.AccountsMgmt().V1().Accounts().Account(subscription.Creator().ID()).Get().Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get creator account: %w", err)
	}

	creator, ok := accountResponse.GetBody()
	if !ok {
		return nil, fmt.Errorf("failed to get creator from subscription")
	}

	return creator, nil
}

// UserBannedError is returned when a user is banned
type UserBannedError struct {
	UserID         string
	BanCode        string
	BanDescription string
}

func (e *UserBannedError) Error() string {
	return fmt.Sprintf("user %s is banned: %s - %s", e.UserID, e.BanCode, e.BanDescription)
}
