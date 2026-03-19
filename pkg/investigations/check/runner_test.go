package check

import (
	"errors"
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
)

// MockCheck for testing
type MockCheck struct {
	name   string
	passed bool
	err    error
}

func (m *MockCheck) Name() string {
	return m.name
}

func (m *MockCheck) Run(resources *investigation.Resources) (bool, error) {
	return m.passed, m.err
}

func (m *MockCheck) AppendToNotes(notes *notewriter.NoteWriter, passed bool, err error) {
	// No-op for testing - tests don't verify note output
}

func TestRunner_SingleCheck_Pass(t *testing.T) {
	runner := NewRunner()
	runner.Add(&MockCheck{name: "test_check", passed: true, err: nil})

	runner.Run(nil)

	if !runner.AllPassed() {
		t.Error("Expected AllPassed to be true")
	}

	if runner.HasFailures() {
		t.Error("Expected HasFailures to be false")
	}

	results := runner.Results()
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	if !results[0].Passed {
		t.Error("Expected check to pass")
	}
}

func TestRunner_SingleCheck_Fail(t *testing.T) {
	testErr := errors.New("check failed")
	runner := NewRunner()
	runner.Add(&MockCheck{name: "test_check", passed: false, err: testErr})

	runner.Run(nil)

	if runner.AllPassed() {
		t.Error("Expected AllPassed to be false")
	}

	if !runner.HasFailures() {
		t.Error("Expected HasFailures to be true")
	}

	results := runner.Results()
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	if results[0].Passed {
		t.Error("Expected check to fail")
	}

	if results[0].Error != testErr {
		t.Errorf("Expected error %v, got %v", testErr, results[0].Error)
	}
}

func TestRunner_MultipleChecks(t *testing.T) {
	runner := NewRunner()
	runner.Add(&MockCheck{name: "check1", passed: true, err: nil})
	runner.Add(&MockCheck{name: "check2", passed: true, err: nil})
	runner.Add(&MockCheck{name: "check3", passed: false, err: errors.New("failed")})

	runner.Run(nil)

	if runner.AllPassed() {
		t.Error("Expected AllPassed to be false")
	}

	if !runner.HasFailures() {
		t.Error("Expected HasFailures to be true")
	}

	results := runner.Results()
	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	// Check individual results
	if !results[0].Passed {
		t.Error("Expected check1 to pass")
	}
	if !results[1].Passed {
		t.Error("Expected check2 to pass")
	}
	if results[2].Passed {
		t.Error("Expected check3 to fail")
	}
}

func TestRunner_Results_Order(t *testing.T) {
	runner := NewRunner()
	runner.Add(&MockCheck{name: "first", passed: true, err: nil})
	runner.Add(&MockCheck{name: "second", passed: true, err: nil})
	runner.Add(&MockCheck{name: "third", passed: true, err: nil})

	runner.Run(nil)

	results := runner.Results()
	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	expected := []struct {
		name   string
		passed bool
	}{
		{"first", true},
		{"second", true},
		{"third", true},
	}

	for i, exp := range expected {
		if results[i].Check.Name() != exp.name {
			t.Errorf("Result[%d]: expected name %q, got %q", i, exp.name, results[i].Check.Name())
		}
		if results[i].Passed != exp.passed {
			t.Errorf("Result[%d]: expected passed=%v, got %v", i, exp.passed, results[i].Passed)
		}
	}
}

func TestRunner_Add_Variadic(t *testing.T) {
	runner := NewRunner()

	failErr := errors.New("failed")

	// Add multiple checks at once
	runner.Add(
		&MockCheck{name: "check1", passed: true, err: nil},
		&MockCheck{name: "check2", passed: true, err: nil},
		&MockCheck{name: "check3", passed: false, err: failErr},
	)

	runner.Run(nil)

	results := runner.Results()
	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	expected := []struct {
		name   string
		passed bool
		err    error
	}{
		{"check1", true, nil},
		{"check2", true, nil},
		{"check3", false, failErr},
	}

	for i, exp := range expected {
		if results[i].Check.Name() != exp.name {
			t.Errorf("Result[%d]: expected name %q, got %q", i, exp.name, results[i].Check.Name())
		}
		if results[i].Passed != exp.passed {
			t.Errorf("Result[%d]: expected passed=%v, got %v", i, exp.passed, results[i].Passed)
		}
		if results[i].Error != exp.err {
			t.Errorf("Result[%d]: expected error %v, got %v", i, exp.err, results[i].Error)
		}
	}
}
