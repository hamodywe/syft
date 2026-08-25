package format

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/internal/testutil"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Test_SPDXSourceSurvivesEncodeDecode covers every SPDX version syft can write:
// reading back a document syft itself produced must recover the source rather
// than leave the scan target in the package list. Only 2.3 and later carry
// primaryPackagePurpose, which is what identifies the document root, so the
// earlier versions rely on the identifier instead.
func Test_SPDXSourceSurvivesEncodeDecode(t *testing.T) {
	original := testutil.DirectoryInput(t, t.TempDir())

	var encoders []sbom.FormatEncoder
	for _, v := range spdxjson.SupportedVersions() {
		enc, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.EncoderConfig{Version: v})
		require.NoError(t, err)
		encoders = append(encoders, enc)
	}
	for _, v := range spdxtagvalue.SupportedVersions() {
		enc, err := spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.EncoderConfig{Version: v})
		require.NoError(t, err)
		encoders = append(encoders, enc)
	}

	for _, enc := range encoders {
		t.Run(string(enc.ID())+"@"+enc.Version(), func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, original))

			decoded, _, _, err := Decode(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)
			require.NotNil(t, decoded)

			assert.Equal(t, original.Source.Name, decoded.Source.Name, "document name lost on decode")
			assert.IsType(t, source.DirectoryMetadata{}, decoded.Source.Metadata)

			var names []string
			for _, p := range decoded.Artifacts.Packages.Sorted() {
				names = append(names, p.Name)
			}
			assert.Equal(t, []string{"package-1", "package-2"}, names, "the scan target was decoded as a package")
		})
	}
}
