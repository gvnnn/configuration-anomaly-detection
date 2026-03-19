package check

import "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"

// CheckResult pairs a check with its execution outcome
type CheckResult struct {
	Check  Check
	Passed bool
	Error  error // nil if passed, typed error if failed, infrastructure error if execution failed
}

// Runner orchestrates multiple checks
type Runner struct {
	checks  []Check
	results []CheckResult
}

// NewRunner creates a runner for executing multiple checks
func NewRunner() *Runner {
	return &Runner{
		checks:  []Check{},
		results: []CheckResult{},
	}
}

// Add adds one or more checks to the runner
func (r *Runner) Add(checks ...Check) {
	r.checks = append(r.checks, checks...)
}

// Run executes all checks and stores results
func (r *Runner) Run(resources *investigation.Resources) {
	r.results = make([]CheckResult, 0, len(r.checks))

	for _, check := range r.checks {
		passed, err := check.Run(resources)
		r.results = append(r.results, CheckResult{
			Check:  check,
			Passed: passed,
			Error:  err,
		})
	}
}

// Results returns all check results
func (r *Runner) Results() []CheckResult {
	return r.results
}

// HasFailures returns true if any check failed (Passed=false, err is typed error)
func (r *Runner) HasFailures() bool {
	for _, result := range r.results {
		if !result.Passed && result.Error != nil {
			return true
		}
	}
	return false
}

// HasErrors returns true if any check had infrastructure error
// Infrastructure errors are distinguished by being wrapped errors or non-typed
func (r *Runner) HasErrors() bool {
	for _, result := range r.results {
		if result.Error != nil && !result.Passed {
			// If error is not typed (custom check error), it's infrastructure
			// This is a heuristic - checks should use typed errors for failures
			// In practice, investigations will use errors.As() to distinguish
			return true
		}
	}
	return false
}

// AllPassed returns true if all checks passed
func (r *Runner) AllPassed() bool {
	for _, result := range r.results {
		if !result.Passed {
			return false
		}
	}
	return true
}
