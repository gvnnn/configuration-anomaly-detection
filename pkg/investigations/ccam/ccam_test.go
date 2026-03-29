package ccam

import (
	"errors"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

func TestEvaluateRandomError(t *testing.T) {
	timeoutError := errors.New("credentials are there, error is different: timeout")
	input := investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:           nil,
			ClusterDeployment: nil,
			AwsClient:         nil,
			OcmClient:         nil,
			PdClient:          nil,
		},
		BuildError: timeoutError,
	}

	inv := CloudCredentialsCheck{}

	_, err := inv.Run(&input)
	if err.Error() != timeoutError.Error() {
		t.Fatalf("Expected error %v, but got %v", timeoutError, err)
	}
}

func TestActions(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		clusterState    cmv1.ClusterState
		expectedActions []types.Action
	}{
		{
			name: "ccam-cluster-is-ready",
			err: investigation.AWSClientError{
				Err: errors.New("Failed to find trusted relationship to support role 'RH-Technical-Support-Access'"),
			},
			clusterState: cmv1.ClusterStateReady,
			expectedActions: []types.Action{
				&executor.LimitedSupportAction{
					Reason: &ocm.LimitedSupportReason{
						Summary: "Restore missing cloud credentials",
						Details: "Your cluster requires you to take action because Red Hat is not able to access the infrastructure with the provided credentials. Please restore the credentials and permissions provided during install",
					},
					Context: "CCAM",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := investigation.ResourceBuilderMock{
				Resources: &investigation.Resources{
					Cluster:           nil,
					ClusterDeployment: nil,
					AwsClient:         nil,
					OcmClient:         nil,
					PdClient:          nil,
				},
				BuildError: tt.err,
			}

			inv := CloudCredentialsCheck{}

			res, _ := inv.Run(&input)

			if len(res.Actions) != len(tt.expectedActions) {
				t.Fatalf("wrong number of actions, want %d, got %d", len(tt.expectedActions), len(res.Actions))
			}
		})
	}
}
