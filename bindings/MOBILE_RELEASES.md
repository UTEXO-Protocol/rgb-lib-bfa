# Public BFA mobile releases

The existing source Release workflow resolves a single commit SHA before building.
When `BFA_MOBILE_RELEASES_ENABLED=true`, successful source releases dispatch
`rgb-lib-bfa-release` to `UTEXO-Protocol/rgb-lib-kotlin` and
`UTEXO-Protocol/rgb-lib-swift`. Both receive exactly the same payload:

```json
{
  "version": "v0.3.0-beta.7-bfa",
  "source_sha": "<full 40-character source commit SHA>",
  "source_repository": "UTEXO-Protocol/rgb-lib-bfa"
}
```

The package version is the source release tag without its leading `v`, plus
`-bfa`. This keeps BFA versions separate from ordinary rgb-lib releases. On a
manual source release, an existing tag must resolve to the selected commit;
the workflow refuses to build one commit and label it with another commit's tag.

## One-time setup

1. Merge the new BFA workflows into both binding repositories' **default
   branches**. GitHub delivers repository dispatches only to workflows there.
2. Keep this source repository private; both binding repositories must be public.
   A private repository's release attachments are not anonymously downloadable.
3. In each binding repository, set `BFA_SOURCE_READ_TOKEN` with read-only Contents
   access to this repository. Their CI checks out the exact SHA without persisting
   the token. Only compiled packages and generated language bindings are uploaded.
4. Configure the existing Maven Central and GPG secrets in rgb-lib-kotlin. See
   its README for names. Allow the publish jobs to write Contents in the public
   binding repositories.
5. Here, configure `BFA_BINDINGS_DISPATCH_TOKEN` with Contents write permission
   on both binding repositories (needed for repository dispatch).
6. Manually run both BFA workflows using the same version and SHA, leaving
   `publish=false`. Validate Android and iOS integration using their build
   artifacts. Do not enable automatic publication until both builds pass.
7. Set repository variable `BFA_MOBILE_RELEASES_ENABLED` to `true` to enable
   automatic publication on subsequent successful source releases.

## Deliverables

- Android: `com.utexo:rgb-lib-bfa-android:<version>` on Maven Central and a public
  AAR at the Kotlin repository's `bfa-v<version>` GitHub Release. Supports API 21+
  with arm64-v8a and x86_64.
- Apple: a public `<version>` GitHub Release in the Swift repository with an
  XCFramework ZIP and a complete Swift distribution ZIP. Supports iOS 16+ devices,
  ARM64/Intel simulators and macOS 12+. The complete archive can be vendored into
  rgb-sdk-rn's CocoaPods integration; SPM uses the tagged manifest and sources.
- Each platform publishes `version.json` and `SHA256SUMS`; compare their
  `source_commit` values to verify that both use the same pinned source.

No source code is mirrored into public branches. The existing Go dispatch stays
unchanged. Downstream builds run independently: source workflow success confirms
that dispatch succeeded, not that both mobile packages were published. Check both
mobile workflows before declaring the SDK release ready. If one fails, rerun or
recover that platform with the same version and SHA; never substitute a branch tip.

For retries after publication has partially succeeded, follow the recovery notes
in the corresponding binding README. Maven versions and published tags must not
be overwritten. Changes to the React Native SDK itself are a separate integration
step; its current RGBLightningNode dependency is not replaced by these workflows.
