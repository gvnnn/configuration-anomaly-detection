// Package ccam Cluster Credentials Are Missing (CCAM) provides a service for detecting missing cluster credentials
package ccam

import (
	"errors"
	"fmt"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/check"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

type CloudCredentialsCheck struct{}

var ccamLimitedSupport = &ocm.LimitedSupportReason{
	Summary: "Restore missing cloud credentials",
	Details: "Your cluster requires you to take action because Red Hat is not able to access the infrastructure with the provided credentials. Please restore the credentials and permissions provided during install",
}

// Evaluates if the awsError is a cluster credentials are missing error. If it determines that it is,
// the cluster is placed into limited support (if the cluster state allows it), otherwise an error is returned.
func (c *CloudCredentialsCheck) Run(r investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	awsCreds := check.AWSCredentials{}
	err := awsCreds.Check(r)

	crpErr := &check.CustomerRemovedPermissionsErr{}
	infraErr := &investigation.InfrastructureError{}

	if errors.As(err, infraErr) {
		// We aren't able to jumpRole because of an error that is different than
		// a removed support role/policy or removed installer role/policy
		// This would normally be a backplane failure.
		return result, err
	}

	if errors.As(err, crpErr) {
		clusterState := crpErr.ClusterState
		result.StopInvestigations = err

		// The jumprole failed because of a missing support role/policy:
		// we need to figure out if we cluster state allows us to set limited support
		// (the cluster is in a ready state, not uninstalling, installing, etc.)

		result.Actions = append(result.Actions, remediateState(clusterState)...)
	}
	return result, err
}

func remediateState(clusterState cmv1.ClusterState) []types.Action {
	actions := []types.Action{}

	logging.Debug("Checking cluster state: ", clusterState)

	switch clusterState {
	case cmv1.ClusterStateReady:
		// Cluster is in functional state but we can't jumprole to it: post limited support
		actions = []types.Action{
			executor.NewLimitedSupportAction(ccamLimitedSupport.Summary, ccamLimitedSupport.Details, "CCAM").Build(),
			executor.Silence("Cluster credentials are missing - limited support added"),
		}
	case cmv1.ClusterStateUninstalling:
		// A cluster in uninstalling state should not alert primary - we just skip this
		actions = []types.Action{
			executor.Silence(fmt.Sprintf("Skipped adding limited support reason '%s': cluster is already uninstalling", ccamLimitedSupport.Summary)),
		}
	default:
		// Anything else is an unknown state to us and/or requires investigation.
		// E.g. we land here if we run into a CPD alert where credentials were removed (installing state) and don't want to put it in LS yet.
		actions = []types.Action{
			executor.Escalate(fmt.Sprintf("Cluster has invalid cloud credentials (support role/policy is missing) and the cluster is in state '%s'. Please investigate.", clusterState)),
		}
	}

	return actions
}
