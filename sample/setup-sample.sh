#!/usr/bin/bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#

# usage: setup-sample.sh

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"
readonly ROOT_DIR=$(realpath ..)
readonly BIN=${ROOT_DIR}/target/release

./client_helper/setup_client_helper.sh &
./issuer/setup_issuer.sh &
./verifier/setup_verifier.sh &
wait


cargo build --release --features print-trace
mkdir -p ./client_helper/bin ./issuer/bin ./verifier/bin ./setup_service/bin
cp "${BIN}"/crescent-sample-client-helper client_helper/bin/crescent-sample-client-helper
cp "${BIN}"/crescent-sample-issuer issuer/bin/crescent-sample-issuer
cp "${BIN}"/crescent-sample-verifier verifier/bin/crescent-sample-verifier
cp "${BIN}"/crescent-sample-setup-service setup_service/bin/crescent-sample-setup-service


./client/setup_client.sh

cd client
npm run build

# Create json file with base64 encoded mdoc and device private key
# (until we have an issuer to issue mDLs, we use the ones generated in the Crescent lib)
cat <<EOF > mdl.json
{
  "mdoc": "$(base64 -w 0 "../../circuit_setup/inputs/mdl1/mdl.cbor")",
  "devicePrivateKey": "$(base64 -w 0 "../../circuit_setup/inputs/mdl1/device.prv")"
}
EOF

cd ..
