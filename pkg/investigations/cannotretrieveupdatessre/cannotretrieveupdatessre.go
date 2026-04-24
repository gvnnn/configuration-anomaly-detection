package cannotretrieveupdatessre

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/pipeline"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/version"
)

type Step struct{}

// Run executes the investigation for the CannotRetrieveUpdatesSRE alert
func (s *Step) Run(_ context.Context, pc *pipeline.PipelineContext) (pipeline.StepResult, error) {
	result := pipeline.StepResult{}
	r, err := pc.ResourceBuilder.WithAwsClient().WithClusterDeployment().Build()
	if err != nil {
		return result, err
	}
	notes := notewriter.New("CannotRetrieveUpdatesSRE", logging.RawLogger)

	// Run network verifier
	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		notes.AppendWarning("NetworkVerifier failed to run:\n\t %s", err.Error())
	} else {
		switch verifierResult {
		case networkverifier.Failure:
			notes.AppendWarning("NetworkVerifier found unreachable targets. \n \n Verify and send service log if necessary: \n osdctl servicelog post --cluster-id %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=%s", r.Cluster.ID(), failureReason)
		case networkverifier.Success:
			notes.AppendSuccess("Network verifier passed")
		}
	}

	r, err = pc.ResourceBuilder.WithK8sClient().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			notes.AppendWarning("%s", msg)
			result.Actions = append(
				executor.NoteAndReportFrom(notes, r.Cluster.ID(), s.Name()),
				executor.Escalate(msg),
			)
			return result, nil
		}
		return result, investigation.WrapInfrastructure(err, "Resource build error")
	}

	// Check ClusterVersion
	clusterVersion, err := version.GetClusterVersion(r.K8sClient)
	if err != nil {
		notes.AppendWarning("Failed to get ClusterVersion: %s", err.Error())
	} else {
		notes.AppendSuccess("ClusterVersion found: %s", clusterVersion.Status.Desired.Version)

		failureReason := getUpdateRetrievalFailures(clusterVersion)
		if failureReason != "" {
			logging.Warnf("Detected ClusterVersion issue: %s", failureReason)
			notes.AppendWarning("ClusterVersion related issue detected: %s. Current version %s not found in channel %s",
				failureReason, clusterVersion.Status.Desired.Version, clusterVersion.Spec.Channel)
		}
	}
	notes.AppendWarning("Alert escalated to on-call primary for review and please check the ClusterVersion.")
	result.Actions = append(
		executor.NoteAndReportFrom(notes, r.Cluster.ID(), s.Name()),
		executor.Escalate("CannotRetrieveUpdatesSRE investigation completed - manual review required"),
	)
	return result, nil
}

// getUpdateRetrievalFailures checks for update retrieval failures in the ClusterVersion
func getUpdateRetrievalFailures(clusterVersion *configv1.ClusterVersion) string {
	for _, condition := range clusterVersion.Status.Conditions {
		msg, found := checkCondition(condition)
		if found {
			return msg
		}
	}
	return ""
}

func checkCondition(condition configv1.ClusterOperatorStatusCondition) (string, bool) {
	if condition.Type != "RetrievedUpdates" {
		return "", false
	}
	if condition.Status == configv1.ConditionFalse {
		return fmt.Sprintf("(Reason: %s). %s", condition.Reason, condition.Message), true
	}
	return "", false
}

func (s *Step) Name() string {
	return "cannotretrieveupdatessre"
}
