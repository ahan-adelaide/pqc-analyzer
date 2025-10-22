package analyzer_test

import (
	"testing"

	"github.com/ahan-adelaide/pqc-analyzer/analyzer"
	"golang.org/x/tools/go/analysis"
)

func TestAnalyzer(t *testing.T) {
	err := analysis.Validate([]*analysis.Analyzer{&analyzer.PqcAnalyzer})
	if err != nil {
		t.Errorf("invalid analyzer: %s", err.Error())
	}
}
