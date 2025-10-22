// Package analyzer implements the static analysis tool for quantum-vulnerable
// dependency detection.
package analyzer

import (
	"flag"
	"fmt"
	"go/ast"
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
}

// Imports that are quantum-vulnerable because they
// implement integer factorization-based cryptography.
var ifImportPaths = []string{
	"crypto/rsa",
	"crypto/dsa",
}

// Imports that are quantum-vulnerable because they
// implement a quantum-vulnerable key exchange algorithm
// that can be replaced by "crypto/mlkem"
var keyExchangePaths = []string{
	"crypto/ecdh",
}

// Identifiers of functions that implement quantum-vulnerable algorithms.
var fnIdentifiers = []string{
	"DecryptOAEP",
	"DecryptPKCS1v15",
	"DecryptPKCS1v15SessionKey",
	"EncryptOAEP",
	"EncryptPKCS1v15",
	"SignPKCS1v15",
	"SignPSS",
	"VerifyPKCS1v15",
	"VerifyPSS",
	"SignASN1",
	"VerifyASN1",
	"NewTripleDESCipher",
	"x509.MarshalPKCS1PrivateKey",
	"x509.ParsePKCS1PrivateKey",
	"x509.ParseECPrivateKey",
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
		
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			
			if funcDecl.Body != nil {
				continue
			}
			
			for _, token := range funcDecl.Body.List {
				if assignment, ok := token.(*ast.AssignStmt); ok {
					for _, expr := range assignment.Rhs {
						if callExpr, ok := expr.(*ast.CallExpr); ok {
							if slices.Contains(fnIdentifiers, callExpr.Fun.(*ast.Ident).Name) {
								pass.Reportf(callExpr.Fun.Pos(), "function %s is quantum-vulnerable", callExpr.Fun.(*ast.Ident).Name)
							}
						}
					}
				}
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
