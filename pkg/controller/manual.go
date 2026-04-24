package controller

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
)

// shortNameToInvestigation maps short flag names to their corresponding investigation names.
var shortNameToInvestigation = map[string]string{
	"ai":                       "aiassisted",
	"can-not-retrieve-updates": "cannotretrieveupdatessre",
	"chgm":                     "Cluster Has Gone Missing (CHGM)",
	"cmbb":                     "clustermonitoringerrorbudgetburn",
	"cpd":                      "ClusterProvisioningDelay",
	"etcd-quota-low":           "etcddatabasequotalowspace",
	"insightsoperatordown":     "insightsoperatordown",
	"machine-health-check":     "machinehealthcheckunterminatedshortcircuitsre",
	"must-gather":              "mustgather",
	"restart-controlplane":     "restartcontrolplane",
	"upgrade-config":           "upgradeconfigsyncfailureover4hr",
}

type ManualController struct {
	config CommonConfig
	manual ManualConfig
	investigationRunner
}

func (c *ManualController) Investigate(ctx context.Context) error {
	if c.manual.DryRun {
		c.logger.Info("DRY RUN MODE")
	}

	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	experimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)

	name := c.manual.InvestigationName
	if fullName, ok := shortNameToInvestigation[name]; ok {
		name = fullName
	}

	pipelineDef := investigations.GetPipelineByName(name, experimentalEnabled)
	if pipelineDef == nil {
		availableInvestigations := make([]string, 0, len(shortNameToInvestigation))
		for shortName, longName := range shortNameToInvestigation {
			format := fmt.Sprintf("- %s (%s)", shortName, longName)
			availableInvestigations = append(availableInvestigations, format)
		}
		investigationList := strings.Join(availableInvestigations, "\n")
		return fmt.Errorf("unknown investigation: %s - must be one of:\n%s", c.manual.InvestigationName, investigationList)
	}

	return c.runPipeline(ctx, c.manual.ClusterId, *pipelineDef, nil)
}
