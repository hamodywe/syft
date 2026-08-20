package java

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parseGradleVersionsLock(t *testing.T) {
	fixture := "testdata/gradle/versions.lock"

	expected := []pkg.Package{
		versionsLockPackage("com.fasterxml.jackson.core", "jackson-annotations", "2.12.3"),
		versionsLockPackage("com.google.guava", "guava", "30.1.1-jre"),
		versionsLockPackage("com.squareup.okhttp3", "okhttp", "3.12.0"),
		versionsLockPackage("org.apache.commons", "commons-text", "1.8"),
		// the test dependencies section is cataloged too, the same as the test configurations of a gradle.lockfile
		versionsLockPackage("cglib", "cglib-nodep", "3.1"),
		versionsLockPackage("junit", "junit", "4.13.2"),
	}

	for i := range expected {
		expected[i].Locations.Add(file.NewLocation(fixture))
	}

	pkgtest.TestFileParser(t, fixture, parseGradleVersionsLock, expected, nil)
}

func Test_versionsLockEntryPattern(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string // group, name, version; nil when the line states no dependency
	}{
		{
			name: "dependency with constraints",
			line: "com.squareup.okhttp3:okhttp:3.12.0 (1 constraints: 38053b3b)",
			want: []string{"com.squareup.okhttp3", "okhttp", "3.12.0"},
		},
		{
			name: "version with a classifier-like suffix",
			line: "com.google.guava:guava:30.1.1-jre (12 constraints: b290ec5e)",
			want: []string{"com.google.guava", "guava", "30.1.1-jre"},
		},
		{
			name: "no constraints recorded",
			line: "joda-time:joda-time:2.2",
			want: []string{"joda-time", "joda-time", "2.2"},
		},
		{
			name: "the header comment",
			line: "# Run ./gradlew writeVersionsLocks to regenerate this file.",
		},
		{
			name: "the test dependencies section header",
			line: "[Test dependencies]",
		},
		{
			name: "a gradle.lockfile line, which states its configurations instead",
			line: "org.apache.commons:commons-text:1.8=compileClasspath,runtimeClasspath",
		},
		{
			name: "an incomplete coordinate",
			line: "org.apache.commons:commons-text (1 constraints: 0a050036)",
		},
		{
			name: "empty",
			line: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := versionsLockEntryPattern.FindStringSubmatch(tt.line)
			if tt.want == nil {
				assert.Nil(t, match)
				return
			}
			if assert.NotNil(t, match) {
				assert.Equal(t, tt.want, []string{match[1], match[2], match[3]})
			}
		})
	}
}

func versionsLockPackage(group, name, version string) pkg.Package {
	return pkg.Package{
		Name:     name,
		Version:  version,
		Language: pkg.Java,
		Type:     pkg.JavaPkg,
		PURL:     "pkg:maven/" + group + "/" + name + "@" + version,
		Metadata: pkg.JavaArchive{
			PomProject: &pkg.JavaPomProject{
				GroupID:    group,
				ArtifactID: name,
				Version:    version,
				Name:       name,
			},
		},
	}
}
