// Pqc-analyzer is a Post-Quantum Cryptography analysis tool for go programs.
//
// It finds where quantum-vulnerable libraries and functions are used in code,
// and warns of them, potentially proposing alternatives.
package main

import (
	"github.com/ahan-adelaide/pqc-analyzer/analyzer"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(&analyzer.PqcAnalyzer)
}
