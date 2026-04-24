package pipeline

import (
	"context"
	"fmt"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type mockStep struct {
	name         string
	actions      []types.Action
	stopPipeline bool
	err          error
	called       bool
}

func (m *mockStep) Name() string { return m.name }
func (m *mockStep) Run(_ context.Context, _ *PipelineContext) (StepResult, error) {
	m.called = true
	if m.err != nil {
		return StepResult{}, m.err
	}
	return StepResult{Actions: m.actions, StopPipeline: m.stopPipeline}, nil
}

type nopAction struct{ t string }

func (a *nopAction) Type() string                                              { return a.t }
func (a *nopAction) Validate() error                                           { return nil }
func (a *nopAction) Execute(_ context.Context, _ *types.ExecutionContext) error { return nil }

func newCluster() *cmv1.Cluster {
	c, _ := cmv1.NewCluster().ID("test").Build()
	return c
}

type nopExecutor struct{}

func (e *nopExecutor) Execute(_ context.Context, _ *executor.ExecutorInput) error { return nil }

func newPCtx() *PipelineContext {
	return &PipelineContext{
		ResourceBuilder: &investigation.ResourceBuilderMock{
			Resources: &investigation.Resources{Cluster: newCluster()},
		},
		Executor:    &nopExecutor{},
		Logger:      zap.NewNop().Sugar(),
		StepResults: make(map[string]StepResult),
	}
}

func reg(steps ...Step) map[string]Step {
	m := make(map[string]Step)
	for _, s := range steps {
		m[s.Name()] = s
	}
	return m
}

func boolp(v bool) *bool       { return &v }
func floatp(v float64) *float64 { return &v }

func TestRunner_StepsExecuteInOrder(t *testing.T) {
	s1 := &mockStep{name: "a"}
	s2 := &mockStep{name: "b"}
	s3 := &mockStep{name: "c"}
	r := NewRunner(reg(s1, s2, s3), &DeterministicSampler{Result: true})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a"}, {Name: "b"}, {Name: "c"},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.NoError(t, err)
	assert.True(t, s1.called)
	assert.True(t, s2.called)
	assert.True(t, s3.called)
}

func TestRunner_StopPipeline(t *testing.T) {
	s1 := &mockStep{name: "a", stopPipeline: true}
	s2 := &mockStep{name: "b"}
	r := NewRunner(reg(s1, s2), &DeterministicSampler{Result: true})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a"}, {Name: "b"},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.NoError(t, err)
	assert.True(t, s1.called)
	assert.False(t, s2.called)
}

func TestRunner_StopOnActions(t *testing.T) {
	s1 := &mockStep{name: "a", actions: []types.Action{&nopAction{t: "note"}}}
	s2 := &mockStep{name: "b"}
	r := NewRunner(reg(s1, s2), &DeterministicSampler{Result: true})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a", StopOnActions: true}, {Name: "b"},
	}}
	pc := newPCtx()
	err := r.Run(context.Background(), def, pc)
	require.NoError(t, err)
	assert.True(t, s1.called)
	assert.False(t, s2.called)
}

func TestRunner_StopOnActions_NoActionsContinues(t *testing.T) {
	s1 := &mockStep{name: "a"} // no actions
	s2 := &mockStep{name: "b"}
	r := NewRunner(reg(s1, s2), &DeterministicSampler{Result: true})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a", StopOnActions: true}, {Name: "b"},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.NoError(t, err)
	assert.True(t, s1.called)
	assert.True(t, s2.called)
}

func TestRunner_DisabledStep(t *testing.T) {
	s1 := &mockStep{name: "a"}
	s2 := &mockStep{name: "b"}
	r := NewRunner(reg(s1, s2), &DeterministicSampler{Result: true})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a", Enabled: boolp(false)}, {Name: "b"},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.NoError(t, err)
	assert.False(t, s1.called)
	assert.True(t, s2.called)
}

func TestRunner_SamplingSkip(t *testing.T) {
	s1 := &mockStep{name: "a"}
	r := NewRunner(reg(s1), &DeterministicSampler{Result: false})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a", SampleRate: floatp(0.5)},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.NoError(t, err)
	assert.False(t, s1.called)
}

func TestRunner_SamplingRun(t *testing.T) {
	s1 := &mockStep{name: "a"}
	r := NewRunner(reg(s1), &DeterministicSampler{Result: true})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a", SampleRate: floatp(0.5)},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.NoError(t, err)
	assert.True(t, s1.called)
}

func TestRunner_StepFilter(t *testing.T) {
	s1 := &mockStep{name: "a"}
	s2 := &mockStep{name: "b"}
	r := NewRunner(reg(s1, s2), &DeterministicSampler{Result: true})
	r.SetStepFilter(func(name string) bool { return name != "a" })

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a"}, {Name: "b"},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.NoError(t, err)
	assert.False(t, s1.called)
	assert.True(t, s2.called)
}

func TestRunner_ErrorPropagation(t *testing.T) {
	s1 := &mockStep{name: "a", err: fmt.Errorf("boom")}
	s2 := &mockStep{name: "b"}
	r := NewRunner(reg(s1, s2), &DeterministicSampler{Result: true})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a"}, {Name: "b"},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
	assert.True(t, s1.called)
	assert.False(t, s2.called)
}

func TestRunner_UnknownStep(t *testing.T) {
	r := NewRunner(map[string]Step{}, &DeterministicSampler{Result: true})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "nonexistent"},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown step")
}

func TestRunner_EmptyPipeline(t *testing.T) {
	r := NewRunner(map[string]Step{}, &DeterministicSampler{Result: true})
	def := Pipeline{Name: "empty"}
	err := r.Run(context.Background(), def, newPCtx())
	require.NoError(t, err)
}

func TestRunner_ResultsAccumulate(t *testing.T) {
	s1 := &mockStep{name: "a"}
	s2 := &mockStep{name: "b"}
	r := NewRunner(reg(s1, s2), &DeterministicSampler{Result: true})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a"}, {Name: "b"},
	}}
	pc := newPCtx()
	err := r.Run(context.Background(), def, pc)
	require.NoError(t, err)
	assert.Len(t, pc.StepResults, 2)
	_, hasA := pc.StepResults["a"]
	_, hasB := pc.StepResults["b"]
	assert.True(t, hasA)
	assert.True(t, hasB)
}

func TestRunner_EvalOrder(t *testing.T) {
	s1 := &mockStep{name: "a"}
	r := NewRunner(reg(s1), &DeterministicSampler{Result: false})
	filterCalled := false
	r.SetStepFilter(func(_ string) bool {
		filterCalled = true
		return true
	})

	def := Pipeline{Name: "test", Steps: []StepConfig{
		{Name: "a", Enabled: boolp(false), SampleRate: floatp(0.5)},
	}}
	err := r.Run(context.Background(), def, newPCtx())
	require.NoError(t, err)
	assert.False(t, s1.called, "disabled step should not run")
	assert.False(t, filterCalled, "filter should not be called for disabled steps")
}
