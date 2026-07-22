module.exports = {
  branches: ["main"],
  tagFormat: "${version}",
  plugins: [
    "@semantic-release/commit-analyzer",
    "@semantic-release/release-notes-generator",
    [
      "@semantic-release/exec",
      {
        prepareCmd: "./scripts/build-release.sh ${nextRelease.version}",
      },
    ],
    [
      "@semantic-release/github",
      {
        assets: ["dist/*.tar.gz", "dist/*.zip", "dist/checksums.txt"],
      },
    ],
  ],
};
