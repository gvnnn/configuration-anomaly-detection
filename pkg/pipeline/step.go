package pipeline

import (
	"context"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"go.uber.org/zap"
)

// Step is the unit of work in a pipeline.
type Step interface {
	Name() string
	Run(ctx context.Context, pc *PipelineContext) (StepResult, error)
}

// StepResult captures the outcome of a single step.
type StepResult struct {
	// Actions to execute (notes, escalations, service logs, etc.)
	Actions []types.Action

	// StopPipeline tells the runner to skip all remaining steps.
	StopPipeline bool
}

// PipelineContext carries shared state through the pipeline.
// ResourceBuilder is the DI mechanism — it caches built resources, so
// multiple steps sharing the same builder don't re-create clients.
type PipelineContext struct {
	ResourceBuilder investigation.ResourceBuilder
	Executor        executor.Executor
	Logger          *zap.SugaredLogger
	DryRun          bool

	// StepResults accumulates outcomes keyed by step name.
	StepResults map[string]StepResult
}

// Pipeline describes which steps to run and in what order.
type Pipeline struct {
	Name       string       `yaml:"name"`
	AlertTitle string       `yaml:"alert_title"`
	Steps      []StepConfig `yaml:"steps"`
}

// StepConfig controls an individual step's behavior within a pipeline.
type StepConfig struct {
	Name          string   `yaml:"name"`
	Enabled       *bool    `yaml:"enabled,omitempty"`
	SampleRate    *float64 `yaml:"sample_rate,omitempty"`
	StopOnActions bool     `yaml:"stop_on_actions,omitempty"`
}

func (s StepConfig) isEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

func (s StepConfig) effectiveSampleRate() float64 {
	if s.SampleRate == nil {
		return 1.0
	}
	return *s.SampleRate
}
