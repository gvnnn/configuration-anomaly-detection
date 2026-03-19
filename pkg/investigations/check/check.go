// Package check provides reusable validation checks for investigations
package check

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
)

// Check represents a reusable validation that can be run across multiple investigations.
// Checks validate conditions and return typed errors for failures, allowing investigations
// to decide appropriate remediations.
type Check interface {
	// Name returns the check identifier (e.g., "ocm_user_ban")
	Name() string

	// Run executes the check and returns:
	// - (true, nil): check passed
	// - (false, CustomError): check failed, error contains typed details
	// - (false, error): infrastructure/execution error
	Run(resources *investigation.Resources) (bool, error)

	// AppendToNotes formats the check result and appends it to notes.
	// The check implementation knows best how to format its own results,
	// including extracting details from typed errors.
	AppendToNotes(notes *notewriter.NoteWriter, passed bool, err error)
}
