package java

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// versionsLockEntryPattern matches a single dependency of a versions.lock file:
//
//	com.squareup.okhttp3:okhttp:3.12.0 (1 constraints: 38053b3b)
//
// The trailing constraint count and hash record which dependents asked for the version, and exist to keep merges
// honest; neither says anything about the package itself, so both are read past. Excluding "=" from the
// coordinate keeps a gradle.lockfile line, which states its configurations that way, from being read as a
// version.
var versionsLockEntryPattern = regexp.MustCompile(`^(?P<group>[^\s:=]+):(?P<name>[^\s:=]+):(?P<version>[^\s:=]+)(?:\s+\([^)]*\))?$`)

// parseGradleVersionsLock parses the lockfile written by palantir/gradle-consistent-versions, a gradle plugin
// that resolves every dependency version up front and records the result in a versions.lock file. That file is
// the whole resolved dependency set, so a project using the plugin can be cataloged without running gradle --
// which is the point for anyone building SBOMs in an environment that has no JVM to build with.
//
// source: https://github.com/palantir/gradle-consistent-versions
func parseGradleVersionsLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case line == "":
			// blank lines separate dependencies to keep merge conflicts small
			continue
		case strings.HasPrefix(line, "#"):
			// the header states how to regenerate the file
			continue
		case strings.HasPrefix(line, "["):
			// "[Test dependencies]" opens the dependencies that only test source sets pull in. They are
			// cataloged along with the rest, the same as the test configurations of a gradle.lockfile are.
			continue
		}

		match := versionsLockEntryPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		pkgs = append(pkgs, newGradleLockfilePackage(lockfileDependency{
			Group:   match[1],
			Name:    match[2],
			Version: match[3],
		}, reader))
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("unable to read versions.lock file: %w", err)
	}

	return pkgs, nil, nil
}
