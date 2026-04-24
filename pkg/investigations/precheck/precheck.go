package precheck

import (
	"context"
	"errors"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/pipeline"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

type Step struct{}

func (s *Step) Name() string { return "precheck" }

// Run checks pre-requisites for a cluster investigation:
// - the cluster's state is supported by CAD for an investigation (= not uninstalling)
// - the cloud provider is supported by CAD (cluster is AWS)
// Performs according pagerduty actions and returns whether CAD needs to investigate the cluster.
func (s *Step) Run(_ context.Context, pc *pipeline.PipelineContext) (pipeline.StepResult, error) {
	result := pipeline.StepResult{}
	r, err := pc.ResourceBuilder.WithCluster().Build()
	if err != nil {
		clusterNotFound := &investigation.ClusterNotFoundError{}
		if errors.As(err, clusterNotFound) {
			logging.Warnf("Cluster not found. Escalating and exiting: %w", clusterNotFound)
			result.Actions = []types.Action{
				executor.Escalate("CAD: Cluster not found."),
			}
			result.StopPipeline = true
			return result, nil
		}
		return result, err
	}
	cluster := r.Cluster
	ocmClient := r.OcmClient

	if cluster.State() == cmv1.ClusterStateUninstalling {
		logging.Info("Cluster is uninstalling and requires no investigation. Silencing alert.")
		return pipeline.StepResult{
			Actions: []types.Action{
				executor.Note("CAD: Cluster is already uninstalling, silencing alert."),
				executor.Silence("CAD: Cluster is already uninstalling, silencing alert."),
			},
			StopPipeline: true,
		}, nil
	}

	if cluster.AWS() == nil {
		logging.Info("Cloud provider unsupported, forwarding to primary.")
		return pipeline.StepResult{
			Actions: []types.Action{
				executor.Note("CAD could not run an automated investigation on this cluster: unsupported cloud provider."),
				executor.Escalate("CAD could not run an automated investigation on this cluster: unsupported cloud provider."),
			},
			StopPipeline: true,
		}, nil
	}

	isAccessProtected, err := ocmClient.IsAccessProtected(cluster)
	if err != nil {
		logging.Warnf("failed to get access protection status for cluster: %v. Escalating for manual handling.", err)
		return pipeline.StepResult{
			Actions: []types.Action{
				executor.Note("CAD could not determine access protection status for this cluster, as CAD is unable to run against access protected clusters, please investigate manually."),
				executor.Escalate("CAD could not determine access protection status for this cluster, as CAD is unable to run against access protected clusters, please investigate manually."),
			},
			StopPipeline: true,
		}, nil
	}
	if isAccessProtected {
		logging.Info("Cluster is access protected. Escalating alert.")
		return pipeline.StepResult{
			Actions: []types.Action{
				executor.Note("CAD is unable to run against access protected clusters. Please investigate."),
				executor.Escalate("CAD is unable to run against access protected clusters. Please investigate."),
			},
			StopPipeline: true,
		}, nil
	}
	return result, nil
}
