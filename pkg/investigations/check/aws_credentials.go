// Package check provides reusable single checks that can be used to compose an investigation
package check

import (
	"errors"
	"fmt"
	"log"
	"regexp"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

type AWSCredentials struct{}

type CustomerRemovedPermissionsErr struct {
	ClusterState cmv1.ClusterState
	Err          error
}

func (c *AWSCredentials) Check(r investigation.ResourceBuilder) error {
	res, err := r.WithAwsClient().Build()

	logging.Info("Investigating possible missing cloud credentials...")
	// Only an AWS error indicates that the permissions are incorrect - all other mean the resource build failed for other reasons
	awsClientErr := &investigation.AWSClientError{}
	if errors.As(err, awsClientErr) {
		logging.Debug("Inspecting AWS error")
		if customerRemovedPermissions := customerRemovedPermissions(awsClientErr.Err.Error()); !customerRemovedPermissions {
			// We aren't able to jumpRole because of an error that is different than
			// a removed support role/policy or removed installer role/policy
			// This would normally be a backplane failure.
			logging.Debug("Unhandled AWS error: ", awsClientErr.Error())
			return investigation.WrapInfrastructure(awsClientErr.Err, "AWS/Backplane infrastructure failure")
		}
		cluster := res.Cluster

		// Return the cluster state to the calling investigation;
		// Investigations determine remediations/actions on an alert by alert basis
		return CustomerRemovedPermissionsErr{
			Err:          err,
			ClusterState: cluster.State(),
		}
	}

	// Not an AWS client error - unmanaged
	return err
}

// userCausedErrors contains the list of backplane returned error strings that we map to
// customer modifications/role deletions.
var userCausedErrors = []string{
	// OCM can't access the installer role to determine the trust relationship on the support role,
	// therefore we don't know if it's the isolated access flow or the old flow, e.g.:
	// status is 404, identifier is '404', code is 'CLUSTERS-MGMT-404' and operation identifier is '<id>': Failed to find trusted relationship to support role 'RH-Technical-Support-Access'
	// See https://issues.redhat.com/browse/OSD-24270
	".*Failed to find trusted relationship to support role 'RH-Technical-Support-Access'.*",

	// OCM role can't access the installer role, this happens when customer deletes/modifies the trust policy of the installer role, e.g.:
	// status is 400, identifier is '400', code is 'CLUSTERS-MGMT-400' and operation identifier is '<id>': Please make sure IAM role 'arn:aws:iam::<ocm_role_aws_id>:role/ManagedOpenShift-Installer-Role' exists, and add 'arn:aws:iam::<id>:role/RH-Managed-OpenShift-Installer' to the trust policy on IAM role 'arn:aws:iam::<id>:role/ManagedOpenShift-Installer-Role': Failed to assume role: User: arn:aws:sts::<id>:assumed-role/RH-Managed-OpenShift-Installer/OCM is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::<customer_aws_id>:role/ManagedOpenShift-Installer-Role
	".*RH-Managed-OpenShift-Installer/OCM is not authorized to perform: sts:AssumeRole on resource.*",

	// Customer deleted the support role, e.g.:
	// status is 404, identifier is '404', code is 'CLUSTERS-MGMT-404' and operation identifier is '<id>': Support role, used with cluster '<cluster_id>', does not exist in the customer's AWS account
	".*Support role, used with cluster '[a-z0-9]{32}', does not exist in the customer's AWS account.*",

	// This error is the response from backplane calls when:
	// trust policy of ManagedOpenShift-Support-Role is changed
	".*could not assume support role in customer's account: .*AccessDenied:.*",

	// Customer removed the `GetRole` permission from the Installer role.
	// Failed to get role: User: arn:aws:sts::<id>:assumed-role/ManagedOpenShift-Installer-Role/OCM is not authorized to perform: iam:GetRole on resource: role ManagedOpenShift-Support-Role because no identity-based policy allows the iam:GetRole action
	".*is not authorized to perform: iam:GetRole on resource: role.*",
}

func customerRemovedPermissions(backplaneError string) bool {
	for _, str := range userCausedErrors {
		re, err := regexp.Compile(str)
		if err != nil {
			// This should never happen on production as we would run into it during unit tests
			log.Fatal("failed to regexp.Compile string in `userCausedErrors`")
		}

		if re.MatchString(backplaneError) {
			return true
		}
	}

	return false
}

func (c CustomerRemovedPermissionsErr) Error() string {
	return fmt.Sprintf("Customer removed permissions (cluster state: %q)", c.ClusterState)
}
