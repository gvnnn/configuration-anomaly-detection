package investigations

import (
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cannotretrieveupdatessre"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/clustermonitoringerrorbudgetburn"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cpd"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/etcddatabasequotalowspace"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/insightsoperatordown"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/machinehealthcheckunterminatedshortcircuitsre"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/mustgather"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/precheck"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/restartcontrolplane"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/upgradeconfigsyncfailureover4hr"
	"github.com/openshift/configuration-anomaly-detection/pkg/pipeline"
)

// StepRegistration ties a step to its alert routing metadata.
type StepRegistration struct {
	Step         pipeline.Step
	AlertTitle   string
	Experimental bool
}

var registeredSteps = []StepRegistration{
	{Step: &chgm.Step{}, AlertTitle: "has gone missing"},
	{Step: &clustermonitoringerrorbudgetburn.Step{}, AlertTitle: "ClusterMonitoringErrorBudgetBurnSRE"},
	{Step: &cpd.Step{}, AlertTitle: "ClusterProvisioningDelay -"},
	{Step: &etcddatabasequotalowspace.Step{}, AlertTitle: "etcdDatabaseQuotaLowSpace"},
	{Step: &insightsoperatordown.Step{}, AlertTitle: "InsightsOperatorDown"},
	{Step: &upgradeconfigsyncfailureover4hr.Step{}, AlertTitle: "UpgradeConfigSyncFailureOver4HrSRE"},
	{Step: &machinehealthcheckunterminatedshortcircuitsre.Step{}, AlertTitle: "MachineHealthCheckUnterminatedShortCircuitSRE"},
	{Step: &restartcontrolplane.Step{}, AlertTitle: "RestartControlPlane"},
	{Step: &cannotretrieveupdatessre.Step{}, AlertTitle: "CannotRetrieveUpdatesSRE", Experimental: true},
	{Step: &mustgather.Step{}, AlertTitle: "CreateMustGather"},
}

// GetPipeline returns the default pipeline for the first step whose AlertTitle
// matches the given alert. Returns nil if no match.
func GetPipeline(alertTitle string, experimental bool) *pipeline.Pipeline {
	for _, reg := range registeredSteps {
		if reg.AlertTitle == "" {
			continue
		}
		if !strings.Contains(alertTitle, reg.AlertTitle) {
			continue
		}
		if reg.Experimental && !experimental {
			continue
		}
		return defaultPipelineFor(reg)
	}
	return nil
}

// GetPipelineByName looks up by step name. Used by manual controller.
func GetPipelineByName(name string, experimental bool) *pipeline.Pipeline {
	for _, reg := range registeredSteps {
		if !strings.Contains(reg.Step.Name(), name) {
			continue
		}
		if reg.Experimental && !experimental {
			continue
		}
		return defaultPipelineFor(reg)
	}
	return nil
}

// BuildStepRegistry returns all registered steps keyed by name,
// including the fixed infrastructure steps (precheck, ccam, title-update).
func BuildStepRegistry() map[string]pipeline.Step {
	reg := map[string]pipeline.Step{
		"precheck":     &precheck.Step{},
		"ccam":         &ccam.Step{},
		"title-update": &pipeline.TitleUpdateStep{Prefix: "[CAD Investigated]"},
	}
	for _, r := range registeredSteps {
		reg[r.Step.Name()] = r.Step
	}
	return reg
}

// defaultPipelineFor builds the standard pipeline that replicates
// the current hardcoded runInvestigation() sequence.
func defaultPipelineFor(reg StepRegistration) *pipeline.Pipeline {
	def := pipeline.Pipeline{
		Name:       reg.Step.Name(),
		AlertTitle: reg.AlertTitle,
		Steps: []pipeline.StepConfig{
			{Name: "precheck"},
			{Name: "ccam"},
			{Name: reg.Step.Name()},
			{Name: "title-update"},
		},
	}

	// CHGM: CCAM finding means AWS creds are gone → stop immediately.
	if reg.AlertTitle == "has gone missing" {
		def.Steps[1].StopOnActions = true
	}

	return &def
}

// GetAvailableStepNames returns step names for user-facing listings.
func GetAvailableStepNames() []string {
	names := make([]string, 0, len(registeredSteps))
	for _, r := range registeredSteps {
		names = append(names, r.Step.Name())
	}
	return names
}
