package controller

import (
	"context"
	"os"
	"strconv"

	"github.com/openshift/configuration-anomaly-detection/pkg/aiconfig"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/pipeline"
)

type PagerDutyController struct {
	config   CommonConfig
	pd       PagerDutyConfig
	pdClient *pagerduty.SdkClient
	investigationRunner
}

func (c *PagerDutyController) Investigate(ctx context.Context) error {
	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	experimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)

	clusterID, err := c.pdClient.RetrieveClusterID()
	if err != nil {
		return err
	}

	c.logger = logging.InitLogger(c.config.LogLevel, c.config.Identifier, clusterID)
	c.logger.Infof("Investigating incident '%s' for service '%s (%s)'", c.pdClient.GetIncidentRef(), c.pdClient.GetServiceID(), c.pdClient.GetServiceName())

	pipelineDef := investigations.GetPipeline(c.pdClient.GetTitle(), experimentalEnabled)

	// AI fallback for unmatched alerts
	if pipelineDef == nil && experimentalEnabled {
		aiConfig, _ := aiconfig.ParseAIAgentConfig()
		if aiConfig != nil && aiConfig.Enabled {
			pipelineDef = &pipeline.Pipeline{
				Name: "aiassisted",
				Steps: []pipeline.StepConfig{
					{Name: "precheck"},
					{Name: "aiassisted"},
				},
			}
		}
	}

	if pipelineDef == nil {
		c.logger.Infof("No pipeline for incident %s, escalating", c.pdClient.GetIncidentRef())
		return c.pdClient.EscalateIncident()
	}

	return c.runPipeline(ctx, clusterID, *pipelineDef, c.pdClient)
}

func escalateDocumentationMismatch(docErr *ocm.DocumentationMismatchError, resources *investigation.Resources, pdClient *pagerduty.SdkClient) {
	message := docErr.EscalationMessage()

	if resources != nil && resources.Notes != nil {
		resources.Notes.AppendWarning("%s", message)
		message = resources.Notes.String()
	}

	if pdClient == nil {
		logging.Errorf("Failed to obtain PagerDuty client, unable to escalate documentation mismatch to PagerDuty notes.")
		return
	}

	if err := pdClient.EscalateIncidentWithNote(message); err != nil {
		logging.Errorf("Failed to escalate documentation mismatch notes to PagerDuty: %v", err)
		return
	}

	logging.Info("Escalated documentation mismatch to PagerDuty")
}
