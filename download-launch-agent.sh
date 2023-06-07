#!/usr/bin/env sh

set -eu pipefail

echo "Installing CircleCI Runner for ${platform}"

base_url="https://circleci-binary-releases.s3.amazonaws.com/circleci-launch-agent"
if [ -z ${agent_version+x} ]; then
    agent_version=$(curl "${base_url}/release.txt")
fi

# Set up the runner directories
echo "Setting up CircleCI Runner directories"
sudo mkdir -p /var/opt/circleci /opt/circleci

# Find appropriate hash cmd
if hash shasum 2>/dev/null; then
  echo "found shasum command"
  alias SHACMD="shasum -a256"
elif hash sha256sum 2>/dev/null; then
  echo "found sha256sum command"
  alias SHACMD="sha256sum"
else
  echo "shasum command found"
  exit 1
fi

# Downloading launch agent
echo "Using CircleCI Launch Agent version ${agent_version}"
echo "Downloading and verifying CircleCI Launch Agent Binary"
curl -sSL "${base_url}/${agent_version}/checksums.txt" -o checksums.txt
file="$(grep -F "${platform}" checksums.txt | cut -d ' ' -f 2 | sed 's/^.//')"
mkdir -p "${platform}"
echo "Downloading CircleCI Launch Agent: ${file}"
curl --compressed -L "${base_url}/${agent_version}/${file}" -o "${file}"

# Verifying download
echo "Verifying CircleCI Launch Agent download"
grep "${file}" checksums.txt | SHACMD --check && chmod +x "${file}"
sudo cp "${file}" "/opt/circleci/circleci-launch-agent" || echo "Invalid checksum for CircleCI Launch Agent, please try download again"
