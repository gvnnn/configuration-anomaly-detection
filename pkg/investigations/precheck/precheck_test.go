package precheck

import (
	"context"
	"errors"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/pipeline"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
)

func TestInvestigation_Run(t *testing.T) {
	type args struct {
		rb *investigation.ResourceBuilderMock
	}
	tests := []struct {
		name       string
		c          *Step
		args       args
		want       pipeline.StepResult
		wantErr    bool
		setupMocks func(*gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster)
	}{
		{
			name: "cloud provider unsupported stops investigation and escalates the alert",
			c:    &Step{},
			want: pipeline.StepResult{
				Actions: []types.Action{
					executor.Note("CAD could not run an automated investigation on this cluster: unsupported cloud provider."),
					executor.Escalate("CAD could not run an automated investigation on this cluster: unsupported cloud provider."),
				},
				StopPipeline: true,
			},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)
				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.GCP(cmv1.NewGCP())
				cluster, _ := builder.Build()

				return pdClient, ocmClient, cluster
			},
		},
		{
			name: "cluster is uninstalling stops investigation and silences the alert",
			c:    &Step{},
			want: pipeline.StepResult{
				Actions: []types.Action{
					executor.Note("CAD: Cluster is already uninstalling, silencing alert."),
					executor.Silence("CAD: Cluster is already uninstalling, silencing alert."),
				},
				StopPipeline: true,
			},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateUninstalling)
				cluster, _ := builder.Build()

				return pdClient, ocmClient, cluster
			},
		},
		{
			name: "access protection status unknown escalates",
			c:    &Step{},
			want: pipeline.StepResult{
				Actions: []types.Action{
					executor.Note("CAD could not determine access protection status for this cluster, as CAD is unable to run against access protected clusters, please investigate manually."),
					executor.Escalate("CAD could not determine access protection status for this cluster, as CAD is unable to run against access protected clusters, please investigate manually."),
				},
				StopPipeline: true,
			},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.AWS(cmv1.NewAWS())
				cluster, _ := builder.Build()

				ocmClient.EXPECT().IsAccessProtected(cluster).Return(false, errors.New("API error"))

				return pdClient, ocmClient, cluster
			},
		},
		{
			name: "access protection enabled escalates",
			c:    &Step{},
			want: pipeline.StepResult{
				Actions: []types.Action{
					executor.Note("CAD is unable to run against access protected clusters. Please investigate."),
					executor.Escalate("CAD is unable to run against access protected clusters. Please investigate."),
				},
				StopPipeline: true,
			},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.AWS(cmv1.NewAWS())
				cluster, _ := builder.Build()

				ocmClient.EXPECT().IsAccessProtected(cluster).Return(true, nil)

				return pdClient, ocmClient, cluster
			},
		},
		{
			name:    "access protection disabled continues investigation",
			c:       &Step{},
			want:    pipeline.StepResult{StopPipeline: false},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.AWS(cmv1.NewAWS())
				cluster, _ := builder.Build()

				ocmClient.EXPECT().IsAccessProtected(cluster).Return(false, nil)

				return pdClient, ocmClient, cluster
			},
		},
		{
			name: "cloud provider unsupported stops investigation",
			c:    &Step{},
			want: pipeline.StepResult{
				Actions: []types.Action{
					executor.Note("CAD could not run an automated investigation on this cluster: unsupported cloud provider."),
					executor.Escalate("CAD could not run an automated investigation on this cluster: unsupported cloud provider."),
				},
				StopPipeline: true,
			},
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.GCP(cmv1.NewGCP())
				cluster, _ := builder.Build()
				return pdClient, ocmClient, cluster
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			pdClient, ocmClient, cluster := tt.setupMocks(mockCtrl)

			mockBuilder := &investigation.ResourceBuilderMock{
				Resources: &investigation.Resources{
					Cluster:   cluster,
					OcmClient: ocmClient,
					PdClient:  pdClient,
				},
			}

			pc := &pipeline.PipelineContext{
				ResourceBuilder: mockBuilder,
				Logger:          zap.NewNop().Sugar(),
				StepResults:     make(map[string]pipeline.StepResult),
			}

			step := &Step{}
			got, err := step.Run(context.Background(), pc)
			if (err != nil) != tt.wantErr {
				t.Errorf("Step.Run() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check StopPipeline
			if got.StopPipeline != tt.want.StopPipeline {
				t.Errorf("Step.Run() StopPipeline = %v, want %v", got.StopPipeline, tt.want.StopPipeline)
			}

			// Check Actions
			if len(tt.want.Actions) != len(got.Actions) {
				t.Errorf("Step.Run() Actions length = %d, want %d", len(got.Actions), len(tt.want.Actions))
				return
			}
			for i, wantAction := range tt.want.Actions {
				if got.Actions[i].Type() != wantAction.Type() {
					t.Errorf("Step.Run() Actions[%d].Type() = %s, want %s", i, got.Actions[i].Type(), wantAction.Type())
				}
			}
		})
	}
}
