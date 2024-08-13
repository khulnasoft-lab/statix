package artifact

import (
	"context"
	"sort"

	"github.com/khulnasoft-lab/statix/analyzer"
	misconf "github.com/khulnasoft-lab/statix/analyzer/config"
	"github.com/khulnasoft-lab/statix/analyzer/secret"
	"github.com/khulnasoft-lab/statix/types"
)

type Option struct {
	AnalyzerGroup     analyzer.Group // It is empty in OSS
	DisabledAnalyzers []analyzer.Type
	DisabledHandlers  []types.HandlerType
	SkipFiles         []string
	SkipDirs          []string
	NoProgress        bool
	Offline           bool
	InsecureSkipTLS   bool

	MisconfScannerOption misconf.ScannerOption
	SecretScannerOption  secret.ScannerOption
}

func (o *Option) Sort() {
	sort.Slice(o.DisabledAnalyzers, func(i, j int) bool {
		return o.DisabledAnalyzers[i] < o.DisabledAnalyzers[j]
	})
	sort.Strings(o.SkipFiles)
	sort.Strings(o.SkipDirs)
}

type Artifact interface {
	Inspect(ctx context.Context) (reference types.ArtifactReference, err error)
	Clean(reference types.ArtifactReference) error
}
