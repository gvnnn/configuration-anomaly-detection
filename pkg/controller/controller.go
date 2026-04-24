package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/managedcloud"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/pipeline"
	"go.uber.org/zap"
)

type PagerDutyConfig struct {
	PayloadPath string
}

func (p *PagerDutyConfig) Validate() error {
	if p.PayloadPath == "" {
		return fmt.Errorf("PayloadPath can not be empty")
	}
	return nil
}

type ManualConfig struct {
	ClusterId         string
	InvestigationName string
	DryRun            bool
}

func (p *ManualConfig) Validate() error {
	if p.ClusterId == "" || p.InvestigationName == "" {
		return fmt.Errorf("ClusterId and InvestigationName can not be empty")
	}
	return nil
}

type CommonConfig struct {
	LogLevel   string
	Identifier string
}

type Controller interface {
	Investigate(ctx context.Context) error
}

type investigationRunner struct {
	ocmClient      *ocm.SdkClient
	bpClient       backplane.Client
	executor       executor.Executor
	logger         *zap.SugaredLogger
	dependencies   *Dependencies
	dryRun         bool
	pipelineRunner *pipeline.Runner
}

type ControllerOptions struct {
	Common CommonConfig
	Pd     *PagerDutyConfig // nil if not via PD
	Manual *ManualConfig    // nil if not manual
}

type Dependencies struct {
	OCMClient           *ocm.SdkClient
	BackplaneClient     backplane.Client
	BackplaneURL        string
	BackplaneProxy      string
	AWSProxy            string
	ExperimentalEnabled bool
}

func (d *Dependencies) Cleanup() {
}

// initializeDependencies loads environment variables and creates shared clients
func initializeDependencies() (*Dependencies, error) {
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return nil, fmt.Errorf("missing required environment variable BACKPLANE_URL")
	}

	backplaneInitialARN := os.Getenv("BACKPLANE_INITIAL_ARN")
	if backplaneInitialARN == "" {
		return nil, fmt.Errorf("missing required environment variable BACKPLANE_INITIAL_ARN")
	}

	backplaneProxy := os.Getenv("BACKPLANE_PROXY")
	awsProxy := os.Getenv("AWS_PROXY")

	managedcloud.SetBackplaneURL(backplaneURL)
	managedcloud.SetBackplaneInitialARN(backplaneInitialARN)
	managedcloud.SetBackplaneProxy(backplaneProxy)
	managedcloud.SetAWSProxy(awsProxy)

	ocmClientID := os.Getenv("CAD_OCM_CLIENT_ID")
	if ocmClientID == "" {
		return nil, fmt.Errorf("missing required environment variable CAD_OCM_CLIENT_ID")
	}

	ocmClientSecret := os.Getenv("CAD_OCM_CLIENT_SECRET")
	if ocmClientSecret == "" {
		return nil, fmt.Errorf("missing required environment variable CAD_OCM_CLIENT_SECRET")
	}

	ocmURL := os.Getenv("CAD_OCM_URL")
	if ocmURL == "" {
		return nil, fmt.Errorf("missing required environment variable CAD_OCM_URL")
	}

	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	experimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)

	ocmClient, err := ocm.New(ocmClientID, ocmClientSecret, ocmURL)
	if err != nil {
		return nil, fmt.Errorf("could not initialize ocm client: %w", err)
	}

	config := backplane.Config{
		OcmClient: ocmClient,
		BaseURL:   backplaneURL,
		ProxyURL:  backplaneProxy,
	}
	bpClient, err := backplane.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("could not construct backplane-client")
	}

	return &Dependencies{
		OCMClient:           ocmClient,
		BackplaneClient:     bpClient,
		BackplaneURL:        backplaneURL,
		BackplaneProxy:      backplaneProxy,
		AWSProxy:            awsProxy,
		ExperimentalEnabled: experimentalEnabled,
	}, nil
}

// Run is the main function to interact with the controller.
func Run(opts ControllerOptions) error {
	deps, err := initializeDependencies()
	if err != nil {
		return err
	}
	defer deps.Cleanup()

	ctrl, err := NewController(opts, deps)
	if err != nil {
		return err
	}

	return ctrl.Investigate(context.Background())
}

// NewController determines which controller to create based on options.
func NewController(opts ControllerOptions, deps *Dependencies) (Controller, error) {
	if (opts.Pd != nil && opts.Manual != nil) ||
		(opts.Pd == nil && opts.Manual == nil) {
		return nil, fmt.Errorf("must specify exactly one controller type")
	}

	stepRegistry := investigations.BuildStepRegistry()
	runner := pipeline.NewRunner(stepRegistry, &pipeline.RandomSampler{})

	if opts.Pd != nil {
		if err := opts.Pd.Validate(); err != nil {
			return nil, fmt.Errorf("invalid webhook config: %w", err)
		}

		payload, err := os.ReadFile(opts.Pd.PayloadPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read webhook payload: %w", err)
		}

		pdClient, err := pagerduty.GetPDClient(payload)
		if err != nil {
			return nil, fmt.Errorf("could not initialize pagerduty client: %w", err)
		}

		logger := logging.InitLogger(opts.Common.LogLevel, opts.Common.Identifier, "")

		return &PagerDutyController{
			config:   opts.Common,
			pd:       *opts.Pd,
			pdClient: pdClient,
			investigationRunner: investigationRunner{
				ocmClient:      deps.OCMClient,
				bpClient:       deps.BackplaneClient,
				executor:       executor.NewWebhookExecutor(deps.OCMClient, pdClient, deps.BackplaneClient, logger),
				logger:         logger,
				dependencies:   deps,
				pipelineRunner: runner,
			},
		}, nil
	}

	if opts.Manual != nil {
		if err := opts.Manual.Validate(); err != nil {
			return nil, fmt.Errorf("invalid manual config: %w", err)
		}

		logger := logging.InitLogger(opts.Common.LogLevel, opts.Common.Identifier, opts.Manual.ClusterId)

		return &ManualController{
			config: opts.Common,
			manual: *opts.Manual,
			investigationRunner: investigationRunner{
				ocmClient:      deps.OCMClient,
				bpClient:       deps.BackplaneClient,
				executor:       executor.NewManualExecutor(deps.OCMClient, deps.BackplaneClient, logger),
				logger:         logger,
				dependencies:   deps,
				dryRun:         opts.Manual.DryRun,
				pipelineRunner: runner,
			},
		}, nil
	}

	return nil, fmt.Errorf("no valid controller configuration provided")
}

func (c *investigationRunner) runPipeline(
	ctx context.Context,
	clusterId string,
	def pipeline.Pipeline,
	pdClient *pagerduty.SdkClient,
) error {
	metrics.Inc(metrics.Alerts, def.Name)

	builder, err := investigation.NewResourceBuilder(
		c.ocmClient, c.bpClient, clusterId, def.Name, c.dependencies.BackplaneURL,
	)
	if err != nil {
		return fmt.Errorf("failed to create resource builder: %w", err)
	}
	if pdClient != nil {
		builder.WithPdClient(pdClient)
	}

	defer func() {
		resources, _ := builder.Build()
		if resources != nil && resources.RestConfig != nil {
			logging.Info("Cleaning cluster API access")
			if cleanErr := resources.RestConfig.Clean(); cleanErr != nil {
				logging.Error(cleanErr)
			}
		}
		if resources != nil && resources.OCClient != nil {
			logging.Info("Cleaning OC kubeconfig file access")
			if cleanErr := resources.OCClient.Clean(); cleanErr != nil {
				logging.Error(cleanErr)
			}
		}
		if err != nil {
			handleCADFailure(err, builder, pdClient)
		}
	}()

	pc := &pipeline.PipelineContext{
		ResourceBuilder: builder,
		Executor:        c.executor,
		Logger:          c.logger,
		DryRun:          c.dryRun,
		StepResults:     make(map[string]pipeline.StepResult),
	}

	err = c.pipelineRunner.Run(ctx, def, pc)
	return err
}

func handleCADFailure(err error, rb investigation.ResourceBuilder, pdClient *pagerduty.SdkClient) {
	logging.Errorf("CAD investigation failed: %v", err)
	resources, err := rb.Build()
	if err != nil {
		logging.Errorf("resource builder failed with error: %v", err)
	}

	var docErr *ocm.DocumentationMismatchError
	if errors.As(err, &docErr) {
		escalateDocumentationMismatch(docErr, resources, pdClient)
		return
	}

	var notes string
	if resources != nil && resources.Notes != nil {
		resources.Notes.AppendWarning("🚨 CAD investigation failed, CAD team has been notified. Please investigate manually. 🚨")
		notes = resources.Notes.String()
	} else {
		notes = "🚨 CAD investigation failed prior to resource initialization, CAD team has been notified. Please investigate manually. 🚨"
	}

	if pdClient != nil {
		pdErr := pdClient.EscalateIncidentWithNote(notes)
		if pdErr != nil {
			logging.Errorf("Failed to escalate notes to PagerDuty: %v", pdErr)
		} else {
			logging.Info("CAD failure & incident notes added to PagerDuty")
		}
	} else {
		logging.Errorf("Failed to obtain PagerDuty client, unable to escalate CAD failure to PagerDuty notes.")
	}
}
