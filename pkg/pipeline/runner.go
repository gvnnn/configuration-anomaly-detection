package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

// StepFilter is a hook for external filtering logic (e.g. PR #776's filters).
// Returns true = run, false = skip. Nil means no filtering.
type StepFilter func(stepName string) bool

// Runner orchestrates step execution within a pipeline.
type Runner struct {
	registry   map[string]Step
	sampler    Sampler
	stepFilter StepFilter
}

func NewRunner(registry map[string]Step, sampler Sampler) *Runner {
	return &Runner{registry: registry, sampler: sampler}
}

// SetStepFilter installs an external filter. This is the rebase seam
// where PR #776's filter evaluation plugs in.
func (r *Runner) SetStepFilter(f StepFilter) {
	r.stepFilter = f
}

const (
	maxRetries     = 3
	initialBackoff = 1 * time.Second
	maxBackoff     = 10 * time.Second
)

func (r *Runner) Run(ctx context.Context, def Pipeline, pc *PipelineContext) error {
	for _, cfg := range def.Steps {
		if !cfg.isEnabled() {
			pc.Logger.Debugf("step %s: disabled, skipping", cfg.Name)
			continue
		}
		if r.stepFilter != nil && !r.stepFilter(cfg.Name) {
			pc.Logger.Debugf("step %s: filtered out, skipping", cfg.Name)
			continue
		}
		if cfg.effectiveSampleRate() < 1.0 && !r.sampler.ShouldRun(cfg.effectiveSampleRate()) {
			pc.Logger.Infof("step %s: sampled out (rate=%.2f)", cfg.Name, cfg.effectiveSampleRate())
			continue
		}

		step, ok := r.registry[cfg.Name]
		if !ok {
			return fmt.Errorf("unknown step %q in pipeline %q", cfg.Name, def.Name)
		}

		result, err := r.runWithRetry(ctx, step, pc)
		if err != nil {
			return err
		}
		pc.StepResults[step.Name()] = result

		if len(result.Actions) > 0 {
			if err := executeStepActions(ctx, pc, result, cfg.Name); err != nil {
				return fmt.Errorf("failed to execute %s actions: %w", cfg.Name, err)
			}
		}

		if result.StopPipeline {
			pc.Logger.Infof("step %s: requested pipeline stop", cfg.Name)
			break
		}
		if cfg.StopOnActions && len(result.Actions) > 0 {
			pc.Logger.Infof("step %s: stop_on_actions triggered", cfg.Name)
			break
		}
	}
	return nil
}

func (r *Runner) runWithRetry(ctx context.Context, step Step, pc *PipelineContext) (StepResult, error) {
	maxAttempts := maxRetries + 1
	var result StepResult
	var err error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err = step.Run(ctx, pc)
		if err == nil {
			if attempt > 1 {
				pc.Logger.Infof("step %s succeeded on attempt %d", step.Name(), attempt)
			}
			return result, nil
		}
		if !investigation.IsInfrastructureError(err) {
			return result, err
		}
		if attempt < maxAttempts {
			backoff := initialBackoff << (attempt - 1)
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			pc.Logger.Warnf("step %s: infra error on attempt %d/%d, retrying in %v: %v",
				step.Name(), attempt, maxAttempts, backoff, err)
			time.Sleep(backoff)
		}
	}
	return result, err
}

func executeStepActions(ctx context.Context, pc *PipelineContext, result StepResult, stepName string) error {
	resources, err := pc.ResourceBuilder.Build()
	if err != nil && resources.Cluster == nil {
		return fmt.Errorf("failed to build resources for action execution: %w", err)
	}

	exec := pc.Executor
	if resources.IsInfrastructureCluster {
		logging.Infof("Infrastructure cluster detected for %s: wrapping executor", stepName)
		exec = executor.NewInfraClusterExecutor(exec, pc.Logger)
	}

	input := &executor.ExecutorInput{
		InvestigationName: stepName,
		Actions:           result.Actions,
		Cluster:           resources.Cluster,
		Notes:             resources.Notes,
		Options: executor.ExecutionOptions{
			DryRun:            pc.DryRun,
			StopOnError:       false,
			MaxRetries:        3,
			ConcurrentActions: true,
		},
	}

	pc.Logger.Infof("executing %d actions for %s", len(result.Actions), stepName)
	return exec.Execute(ctx, input)
}
