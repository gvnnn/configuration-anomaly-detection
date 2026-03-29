// Package check provides reusable single checks that can be used to compose an investigation
package check

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
)

type Checker interface {
	Check(investigation.Resources) error
}
