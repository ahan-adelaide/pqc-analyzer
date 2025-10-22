// Package analyzer implements the static analysis tool for quantum-vulnerable
// dependency detection.
package analyzer

import (
	"flag"
	"fmt"
	"slices"
	"strconv"

	"golang.org/x/tools/go/analysis"
)

// Imports that are quantum-vulnerable because they
// implement elliptic curve-based symmetry cryptography.
var ecImportPaths = []string{
	"crypto/ecdh",
	"crypto/ecdsa",
	"crypto/ed25519",
	"crypto/elliptic",
	"crypto/tls",
}

// Imports that are quantum-vulnerable because they
// implement integer factorization-based cryptography.
var ifImportPaths = []string{
	"crypto/rsa",
	"crypto/dsa",
	"crypto/tls",
}

func pqcAnalyze(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		for _, currImport := range file.Imports {
			importPath, err := strconv.Unquote(currImport.Path.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to analyze package %s: %s", currImport.Path.Value, err.Error())
			}
			if slices.Contains(ecImportPaths, importPath) {
				pass.Reportf(currImport.Pos(), "%s uses quantum-vulnerable elliptic curve cryptography", currImport.Path.Value)
			}
			if slices.Contains(ifImportPaths, importPath) {
				pass.Reportf(currImport.Pos(), "%s uses quantum-vulnerable integer factorization cryptography", currImport.Path.Value)
			}
		}
	}
	
	return nil, nil
}

var PqcAnalyzer = analysis.Analyzer{
	Name: "pqcAnalyzer",
	Doc: `PQC Analyzer


PQC Analyzer looks for instances of quantum-vulnerable functions/libraries being
called/used in a Go codebase, warning of them and potentially suggesting alternatives.
	`,
	Flags: flag.FlagSet{},
	Run: pqcAnalyze,
}
