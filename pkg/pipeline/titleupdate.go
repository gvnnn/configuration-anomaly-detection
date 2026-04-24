package pipeline

import (
	"context"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

// TitleUpdateStep prepends a prefix to the PagerDuty incident title.
type TitleUpdateStep struct {
	Prefix string
}

func (s *TitleUpdateStep) Name() string { return "title-update" }

func (s *TitleUpdateStep) Run(_ context.Context, _ *PipelineContext) (StepResult, error) {
	return StepResult{
		Actions: []types.Action{&executor.PagerDutyTitleUpdate{Prefix: s.Prefix}},
	}, nil
}
