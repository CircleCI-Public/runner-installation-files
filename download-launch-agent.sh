#!/usr/bin/env bash

set -euo pipefail

# Set up runner directory
prefix=/opt/circleci
sudo mkdir -p "${prefix}/workdir"

# Downloading launch agent
echo "Using CircleCI Launch Agent version ${agent_version}"
echo "Downloading and verifying CircleCI Launch Agent Binary"

split_platform=(${platform//// })
echo ${split_platform[0]}
echo ${split_platform[1]}
runner_url="https://runner.circleci.com"
download_response=$(curl -H "Accept: application/json" -H "Content-Type: application/json" --data "{\"os\":\"${split_platform[0]}\", \"arch\":\"${split_platform[1]}\"}" --request GET ${runner_url}/api/v2/runner/download)
url=$(echo ${download_response} | jq -r .url)
checksum=$(echo ${download_response} | jq -r .checksum)

file=circleci-agent
mkdir -p "${platform}"
echo "Downloading CircleCI Launch Agent: ${file}"
curl --compressed -L "${url}" -o "${file}"

# Verifying download
echo "Verifying CircleCI Launch Agent download"
echo "${checksum} ${file}" | sha256sum --check && chmod +x "${file}"; sudo cp "${file}" "${prefix}/circleci-launch-agent" || echo "Invalid checksum for CircleCI Launch Agent, please try download again"
