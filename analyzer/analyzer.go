// Package analyzer implements the static analysis tool for quantum-vulnerable
// dependency detection.
package analyzer

import (
	"flag"
	"fmt"
	"go/ast"
	"slices"
	"strconv"
	"strings"

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

type QvFunction struct {
	FnName  string
	Package string
}

// Identifiers of functions that implement quantum-vulnerable algorithms.
var fnIdentifiers = []QvFunction{
	{"DecryptOAEP", "crypto/rsa"},
	{"DecryptPKCS1v15", "crypto/rsa"},
	{"DecryptPKCS1v15SessionKey", "crypto/rsa"},
	{"EncryptOAEP", "crypto/rsa"},
	{"EncryptPKCS1v15", "crypto/rsa"},
	{"SignPKCS1v15", "crypto/rsa"},
	{"SignPSS", "crypto/rsa"},
	{"VerifyPKCS1v15", "crypto/rsa"},
	{"VerifyPSS", "crypto/rsa"},
	{"SignASN1", "crypto/ecdsa"},
	{"VerifyASN1", "crypto/ecdsa"},
	{"NewTripleDESCipher", "crypto/des"},
	{"MarshalPKCS1PrivateKey", "crypto/x509"},
	{"MarshalECPrivateKey", "crypto/x509"},
	{"ParsePKCS1PrivateKey", "crypto/x509"},
	{"ParseECPrivateKey", "crypto/x509"},
	{"Verify", "crypto/dsa"},
	{"Sign", "crypto/dsa"},
	{"GenerateKey", "crypto/dsa"},
}

func pqcAnalyze(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		if file.Name != nil && strings.HasSuffix(file.Name.Name, "_test") {
			continue
		}
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

			if funcDecl.Body == nil {
				continue
			}

			for _, token := range funcDecl.Body.List {
				switch tokenStmt := token.(type) {
				case *ast.AssignStmt:
					for _, expr := range tokenStmt.Rhs {
						if callExpr, ok := expr.(*ast.CallExpr); ok {
							if selector, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
								if localImportName, ok := selector.X.(*ast.Ident); ok {
									if fnName, vulnerable := vulnerableFunction(file.Imports, localImportName.Name, selector.Sel); vulnerable {
										pass.Reportf(selector.X.Pos(), `function "%s" implements quantum-vulnerable cryptography`, fnName)
									}
								}
							}
						}
					}
				case *ast.ExprStmt:
					if callExpr, ok := tokenStmt.X.(*ast.CallExpr); ok {
						if selector, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
							if localImportName, ok := selector.X.(*ast.Ident); ok {
								if fnName, vulnerable := vulnerableFunction(file.Imports, localImportName.Name, selector.Sel); vulnerable {
									pass.Reportf(selector.X.Pos(), `function "%s" implements quantum-vulnerable cryptography`, fnName)
								}
							}
						}
					}
				}
			}
		}
	}

	return nil, nil
}

func getLocalImportName(importSpec *ast.ImportSpec) string {
	if importSpec.Name != nil {
		return importSpec.Name.Name
	}

	importPath, _ := strconv.Unquote(importSpec.Path.Value)
	importPathComponents := strings.Split(importPath, "/")
	return importPathComponents[len(importPathComponents)-1]
}

// Returns the name of the function (including its package specifier) if true.
func vulnerableFunction(imports []*ast.ImportSpec, localImportName string, fn ast.Expr) (string, bool) {
	idx := slices.IndexFunc(imports, func(importSpec *ast.ImportSpec) bool {
		return getLocalImportName(importSpec) == localImportName
	})

	if idx == -1 {
		return "", false
	}

	importPath, err := strconv.Unquote(imports[idx].Path.Value)
	if err != nil {
		return "", false
	}
	importName := getLocalImportName(imports[idx])
	fnIdent, ok := fn.(*ast.Ident)
	if !ok {
		return "", false
	}
	functionName := fnIdent.Name

	idx = slices.IndexFunc(fnIdentifiers, func(qvFunc QvFunction) bool {
		return qvFunc.FnName == functionName && importPath == qvFunc.Package
	})

	if idx == -1 {
		return "", false
	}

	return importName + "." + functionName, fnIdentifiers[idx].FnName == functionName && fnIdentifiers[idx].Package == importPath
}

var PqcAnalyzer = analysis.Analyzer{
	Name: "pqcAnalyzer",
	Doc: `PQC Analyzer


PQC Analyzer looks for instances of quantum-vulnerable functions/libraries being
called/used in a Go codebase, warning of them and potentially suggesting alternatives.
	`,
	Flags: flag.FlagSet{},
	Run:   pqcAnalyze,
}
