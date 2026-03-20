// Package upgradeconfigsyncfailureover4hr contains functionality for the UpgradeConfigSyncFailureOver4HrSRE investigation
package upgradeconfigsyncfailureover4hr

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/check/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	ocmlib "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pullsecret"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	r, err := rb.Build()
	if err != nil {
		return result, err
	}
	notes := notewriter.New("UpgradeConfigSyncFailureOver4Hr", logging.RawLogger)

	// Run OCM user ban check
	logging.Infof("Checking if user is Banned.")
	userBanCheck := ocm.NewUserBanCheck()
	err = userBanCheck.Run(r)
	userBanCheck.AppendToNotes(notes, err)

	if err != nil {
		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("User validation failed"),
		)
		return result, nil
	}

	// Get user for email validation (needed for pull secret check)
	user, err := ocmlib.GetCreatorFromCluster(r.OcmClient.GetConnection(), r.Cluster)
	if err != nil {
		notes.AppendWarning("Failed getting cluster creator from ocm: %s", err)
		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("Failed to get cluster creator from OCM"),
		)
		return result, nil
	}
	logging.Infof("User ID is: %v", user.ID())

	r, err = rb.WithK8sClient().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			result.Actions = []types.Action{
				executor.Note(msg),
				executor.Escalate(msg),
			}
			return result, nil
		}
		return result, investigation.WrapInfrastructure(err, "Resource build error")
	}

	// Pullsecret validation done via pullsecret package
	ocmEmail := user.Email()
	emailValidation := pullsecret.ValidateEmail(r.K8sClient, ocmEmail)

	for _, warning := range emailValidation.Warnings {
		notes.AppendWarning("%s", warning)
	}

	if emailValidation.IsValid && len(emailValidation.Warnings) == 0 {
		notes.AppendSuccess("Pull Secret matches on cluster and in OCM. Please continue investigation.")
	}

	// Registry credentials validation
	registryValidation, registryResults := pullsecret.ValidateRegistryCredentials(r.K8sClient, r.OcmClient.GetConnection(), user.ID(), ocmEmail)

	// INFO: per-registry validation results at debug level for troubleshooting
	for _, regResult := range registryResults {
		if regResult.Error != nil {
			logging.Debugf("Registry '%s': error=%v", regResult.Registry, regResult.Error)
		} else {
			logging.Debugf("Registry '%s': emailMatch=%v, tokenMatch=%v", regResult.Registry, regResult.EmailMatch, regResult.TokenMatch)
		}
	}

	for _, warning := range registryValidation.Warnings {
		notes.AppendWarning("%s", warning)
	}

	result.Actions = append(
		executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
		executor.Escalate("UpgradeConfigSyncFailure investigation complete"),
	)
	return result, nil
}

func (c *Investigation) Name() string {
	return "upgradeconfigsyncfailureover4hr"
}

func (c *Investigation) AlertTitle() string {
	return "UpgradeConfigSyncFailureOver4HrSRE"
}

func (c *Investigation) Description() string {
	return "Investigates the UpgradeConfigSyncFailureOver4hr alert"
}

func (c *Investigation) IsExperimental() bool {
	return false
}
