// Package clustermonitoringerrorbudgetburn contains remediation for https://issues.redhat.com/browse/OCPBUGS-33863
package clustermonitoringerrorbudgetburn

import (
	"context"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/pipeline"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newUwmConfigMapMisconfiguredSL(docLink string) *ocm.ServiceLog {
	if docLink == "" {
		docLink = ocm.DocumentationLink(ocm.ProductROSA, ocm.DocumentationTopicMonitoringStack)
	}

	return &ocm.ServiceLog{
		Severity:     "Major",
		Summary:      "Action required: review user-workload-monitoring configuration",
		ServiceName:  "SREManualAction",
		Description:  fmt.Sprintf("Your cluster's user workload monitoring is misconfigured: please review the user-workload-monitoring-config ConfigMap in the openshift-user-workload-monitoring namespace. For more information, please refer to the product documentation: %s.", docLink),
		InternalOnly: false,
	}
}

func newUwmAMMisconfiguredSL(docLink string) *ocm.ServiceLog {
	if docLink == "" {
		docLink = ocm.DocumentationLink(ocm.ProductROSA, ocm.DocumentationTopicMonitoringStack)
	}

	return &ocm.ServiceLog{
		Severity:     "Major",
		Summary:      "Action required: review user-workload-monitoring configuration",
		ServiceName:  "SREManualAction",
		Description:  fmt.Sprintf("Your cluster's user workload monitoring is misconfigured: please review the Alert Manager configuration in the opennshift-user-workload-monitoring namespace. For more information, please refer to the product documentation: %s.", docLink),
		InternalOnly: false,
	}
}

func newUwmGenericMisconfiguredSL(docLink string) *ocm.ServiceLog {
	if docLink == "" {
		docLink = ocm.DocumentationLink(ocm.ProductROSA, ocm.DocumentationTopicMonitoringStack)
	}

	return &ocm.ServiceLog{
		Severity:     "Major",
		Summary:      "Action required: review user-workload-monitoring configuration",
		ServiceName:  "SREManualAction",
		Description:  fmt.Sprintf("Your cluster's user workload monitoring is misconfigured: please review the cluster operator status and correct the configuration in the opennshift-user-workload-monitoring namespace. For more information, please refer to the product documentation: %s.", docLink),
		InternalOnly: false,
	}
}

const available = "Available"

type Step struct{}

func (s *Step) Run(_ context.Context, pc *pipeline.PipelineContext) (result pipeline.StepResult, err error) {
	r, err := pc.ResourceBuilder.WithK8sClient().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			result.Actions = []types.Action{
				executor.Escalate(msg),
			}
			return result, nil
		}
		return result, err
	}

	// Initialize PagerDuty note writer
	notes := notewriter.New(r.Name, logging.RawLogger)
	defer func() { r.Notes = notes }()

	// List the monitoring cluster operator
	coList := &configv1.ClusterOperatorList{}
	listOptions := &client.ListOptions{FieldSelector: fields.SelectorFromSet(fields.Set{"metadata.name": "monitoring"})}
	err = r.K8sClient.List(context.TODO(), coList, listOptions)
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("unable to list monitoring clusteroperator: %w", err),
			"K8s API failure listing clusteroperators")
	}

	// Make sure our list output only finds a single cluster operator for `metadata.name = monitoring`
	if len(coList.Items) != 1 {
		notes.AppendWarning("Found %d monitoring clusteroperators, expected 1", len(coList.Items))
		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), s.Name()),
			executor.Escalate("Unexpected monitoring clusteroperator count - manual investigation required"),
		)
		return result, nil
	}
	monitoringCo := coList.Items[0]

	product := ocm.GetClusterProduct(r.Cluster)
	monitoringDocLink := ocm.DocumentationLink(product, ocm.DocumentationTopicMonitoringStack)

	// Check if the UWM configmap is invalid
	// If it is, send a service log and silence the alert.
	if isUWMConfigInvalid(&monitoringCo) {
		notes.AppendAutomation("Customer misconfigured the UWM configmap, sending service log and silencing the alert")
		configMapSL := newUwmConfigMapMisconfiguredSL(monitoringDocLink)

		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), s.Name()),
			executor.NewServiceLogAction(configMapSL.Severity, configMapSL.Summary).
				WithDescription(configMapSL.Description).
				WithServiceName(configMapSL.ServiceName).
				Build(),
			executor.Silence("Customer misconfigured UWM configmap"),
		)
		return result, nil
	}

	if isUWMAlertManagerBroken(&monitoringCo) {
		notes.AppendAutomation("Customer misconfigured the UWM (UpdatingUserWorkloadAlertmanager), sending service log and silencing the alert")
		alertManagerSL := newUwmAMMisconfiguredSL(monitoringDocLink)

		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), s.Name()),
			executor.NewServiceLogAction(alertManagerSL.Severity, alertManagerSL.Summary).
				WithDescription(alertManagerSL.Description).
				WithServiceName(alertManagerSL.ServiceName).
				Build(),
			executor.Silence("Customer misconfigured UWM AlertManager"),
		)
		return result, nil
	}

	if isUWMPrometheusBroken(&monitoringCo) {
		notes.AppendAutomation("Customer misconfigured the UWM (UpdatingUserWorkloadPrometheus), sending service log and silencing the alert")
		genericSL := newUwmGenericMisconfiguredSL(monitoringDocLink)

		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), s.Name()),
			executor.NewServiceLogAction(genericSL.Severity, genericSL.Summary).
				WithDescription(genericSL.Description).
				WithServiceName(genericSL.ServiceName).
				Build(),
			executor.Silence("Customer misconfigured UWM Prometheus"),
		)
		return result, nil
	}

	// The UWM configmap is valid, an SRE will need to manually investigate this alert.
	// Escalate the alert with our findings.
	notes.AppendSuccess("Monitoring CO not degraded due to UWM misconfiguration")
	result.Actions = append(
		executor.NoteAndReportFrom(notes, r.Cluster.ID(), s.Name()),
		executor.Escalate("Monitoring CO not degraded due to UWM misconfiguration - manual investigation required"),
	)
	return result, nil
}

func (s *Step) Name() string {
	return "clustermonitoringerrorbudgetburn"
}

// Check if the `Available` status condition reports a broken UWM config
func isUWMConfigInvalid(monitoringCo *configv1.ClusterOperator) bool {
	symptomStatusString := `the User Workload Configuration from "config.yaml" key in the "openshift-user-workload-monitoring/user-workload-monitoring-config" ConfigMap could not be parsed`

	for _, condition := range monitoringCo.Status.Conditions {
		if condition.Type == available {
			return strings.Contains(condition.Message, symptomStatusString)
		}
	}
	return false
}

func isUWMAlertManagerBroken(monitoringCo *configv1.ClusterOperator) bool {
	symptomStatusString := `UpdatingUserWorkloadAlertmanager: waiting for Alertmanager User Workload object changes failed: waiting for Alertmanager openshift-user-workload-monitoring/user-workload`

	for _, condition := range monitoringCo.Status.Conditions {
		if condition.Type == available {
			return strings.Contains(condition.Message, symptomStatusString)
		}
	}
	return false
}

func isUWMPrometheusBroken(monitoringCo *configv1.ClusterOperator) bool {
	symptomStatusString := `UpdatingUserWorkloadPrometheus: Prometheus "openshift-user-workload-monitoring/user-workload": NoPodReady`

	for _, condition := range monitoringCo.Status.Conditions {
		if condition.Type == available {
			return strings.Contains(condition.Message, symptomStatusString)
		}
	}
	return false
}
