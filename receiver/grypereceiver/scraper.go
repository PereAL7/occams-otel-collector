// Copyright 2021 Occamshub Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grypereceiver

import (
	"context"
	"fmt"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"path"
	"strings"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
	"go.opentelemetry.io/collector/component"
	"go.uber.org/zap"
)

const (
	MetricName = "vulnerability"
	MetricDesc = "Vulnerability found"
	MetricUnit = "u"

	ILName = "grype/vulnerability"

	GrypeUpdateURL = "https://toolbox-data.anchore.io/grype/databases/listing.json"
)

type grypeScraper struct {
	logger           *zap.Logger
	cfg              *Config
	provider         vulnerability.Provider
	metadataProvider vulnerability.MetadataProvider
	status           *db.Status
	dbConf           db.Config
}

func newGrypeScraper(logger *zap.Logger, cfg *Config) *grypeScraper {
	return &grypeScraper{
		logger: logger,
		cfg:    cfg,
	}
}

func (g *grypeScraper) Start(ctx context.Context, host component.Host) error {
	g.logger.Info("Grype scraper initialized.")
	g.dbConf = db.Config{
		DBRootDir:           path.Join("/tmp/", "grype", "db"),
		ListingURL:          GrypeUpdateURL,
		ValidateByHashOnGet: true,
	}
	return nil
}

func (g *grypeScraper) Scrape(ctx context.Context) (pmetric.Metrics, error) {

	if err := g.updateDB(); err != nil {
		g.logger.Error(err.Error())
		return pmetric.Metrics{}, err
	}

	matches := match.NewMatches()
	for _, in := range g.cfg.Include {
		excludes := make([]string, len(g.cfg.Exclude))
		copy(excludes, g.cfg.Exclude)
		providerConfig := pkg.ProviderConfig{
			RegistryOptions:   &image.RegistryOptions{},
			Exclusions:        excludes,
			CatalogingOptions: cataloger.DefaultConfig(),
		}
		packages, con, err := pkg.Provide(fmt.Sprintf("dir:%v", in), providerConfig)
		if err != nil {
			g.logger.Error(err.Error())
			return pmetric.Metrics{}, err
		}
		matchers := matcher.NewDefaultMatchers(matcher.Config{})
		allMatches := grype.FindVulnerabilitiesForPackage(g.provider, con.Distro, matchers, packages)
		g.logger.Info(fmt.Sprintf("Found %v vulnerabilities in dir:%v", allMatches.Count(), in))
		matches.Merge(allMatches)
	}

	md, ilm := g.newMetric()
	for mth := range matches.Enumerate() {
		if err := g.processMatch(&mth, ilm); err != nil {
			g.logger.Error(err.Error())
			return pmetric.Metrics{}, err
		}
	}

	return md, nil
}

func (g *grypeScraper) updateDB() error {
	provider, metadataProvider, dbStatus, err := grype.LoadVulnerabilityDB(g.dbConf, true)
	if err != nil {
		g.logger.Error(err.Error())
		return err
	}
	g.provider = provider
	g.metadataProvider = metadataProvider
	g.status = dbStatus
	return nil
}

func (g *grypeScraper) processMatch(mth *match.Match, ilm pmetric.ScopeMetrics) error {
	m := ilm.Metrics().AppendEmpty()
	m.SetName(MetricName)
	m.SetDataType(pmetric.MetricDataTypeSum)
	m.SetDescription(MetricDesc)
	m.SetUnit(MetricUnit)

	dp := m.Sum().DataPoints().AppendEmpty()
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	dp.SetIntVal(1)

	labels := pcommon.NewMap()
	g.copyMatchToLabels(mth, &labels)

	metadata, err := g.getMetadata(mth.Vulnerability.ID, mth.Vulnerability.Namespace)
	if err != nil {
		g.logger.Error(err.Error())
		return err
	}
	g.copyMetadataToLabels(metadata, &labels)
	labels.CopyTo(dp.Attributes())

	return nil
}

func (g *grypeScraper) getMetadata(
	id string,
	namespace string,
) (*vulnerability.Metadata, error) {
	metadata, err := g.metadataProvider.GetMetadata(id, namespace)
	if err != nil {
		g.logger.Error(err.Error())
		return nil, err
	}
	return metadata, nil
}

func (g *grypeScraper) getLocations(locs []source.Location) []string {
	locations := make([]string, 0)
	for _, l := range locs {
		locations = append(locations, l.RealPath)
	}
	return locations
}

func (g *grypeScraper) newMetric() (pmetric.Metrics, pmetric.ScopeMetrics) {
	md := pmetric.NewMetrics()
	ilm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	ilm.Scope().SetName(ILName)
	ilm.Scope().SetVersion(Version)
	return md, ilm
}

func (g *grypeScraper) copyMetadataToLabels(
	meta *vulnerability.Metadata,
	labels *pcommon.Map,
) {
	labels.Insert("vulnerability.severity", pcommon.NewValueString(strings.ToLower(meta.Severity)))
	labels.Insert("vulnerability.data_source", pcommon.NewValueString(meta.DataSource))
	labels.Insert("vulnerability.namespace", pcommon.NewValueString(meta.Namespace))
	labels.Insert("vulnerability.description", pcommon.NewValueString(meta.Description))
}

func (g *grypeScraper) copyMatchToLabels(
	match *match.Match,
	labels *pcommon.Map,
) {
	labels.Insert("package.id", pcommon.NewValueString(string(match.Package.ID)))
	labels.Insert("package.name", pcommon.NewValueString(match.Package.Name))
	labels.Insert("package.version", pcommon.NewValueString(match.Package.Version))
	labels.Insert("package.language", pcommon.NewValueString(match.Package.Language.String()))
	labels.Insert("package.licences", pcommon.NewValueString(strings.Join(match.Package.Licenses, ",")))
	labels.Insert("package.purl", pcommon.NewValueString(match.Package.PURL))
	labels.Insert("package.type", pcommon.NewValueString(match.Package.Type.PackageURLType()))
	labels.Insert("package.locations", pcommon.NewValueString(strings.Join(g.getLocations(match.Package.Locations.ToSlice()), ",")))
	labels.Insert("vulnerability.id", pcommon.NewValueString(match.Vulnerability.ID))
	labels.Insert("vulnerability.namespace", pcommon.NewValueString(match.Vulnerability.Namespace))
}
