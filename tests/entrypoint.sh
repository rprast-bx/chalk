#!/usr/bin/env bash

set -e

if [ -z "${SSH_AUTH_SOCK:-}" ] && [ -n "${SSH_KEY}" ]; then
    eval "$(ssh-agent)"
    ssh-add <(echo "$SSH_KEY")
fi

if which gpg &> /dev/null; then
    email="chalk@tests.com"
    passphrase="test"
    export GPG_TTY=$(tty)
    if ! gpg -K $email &> /dev/null; then
        gpg \
            --default-new-key-algo "ed25519/cert,sign+cv25519/encr" \
            --yes \
            --batch \
            --quick-generate-key \
            --passphrase $passphrase \
            $email
    fi
    # start gpg agent with the passphrase so that its not prompted later
    echo | gpg \
        --yes \
        --batch \
        --passphrase $passphrase \
        --pinentry-mode loopback \
        --clearsign \
        &> /dev/null
    export GPG_KEY=$(
        gpg \
            -K \
            --keyid-format=LONG \
            chalk@tests.com \
            | grep sec \
            | awk '{print $2}' \
            | cut -d/ -f2
    )
fi

name=insecure_builder

if ! docker buildx inspect $name &> /dev/null; then
    docker buildx create \
        --use \
        --config=<(cat ./data/templates/docker/buildkitd.toml | envsubst | tee /dev/stderr) \
        --name $name \
        node-amd64 \
        > /dev/null
    docker buildx create \
        --append \
        --config=<(cat ./data/templates/docker/buildkitd.toml | envsubst) \
        --name $name \
        node-arm64 \
        > /dev/null
fi

if which "${1:-}" &> /dev/null; then
    exec "$@"
else
    exec pytest "$@"
fi
# { "MAGIC" : "dadfedabbadabbed", "CHALK_ID" : "6WR6AR-SN6H-J6CD-K66GSK", "CHALK_VERSION" : "0.2.2", "TIMESTAMP_WHEN_CHALKED" : 1703173284113, "DATETIME_WHEN_CHALKED" : "2023-12-21T10:41:18.691-05:00", "ARTIFACT_TYPE" : "bash", "CHALK_RAND" : "68f1e00a41633e29", "CODE_OWNERS" : "* @viega\n", "HASH" : "70ec54df6f437adf5f96baa1e9b5459cec14af5a41016e3e200cac9d5ba1106b", "INJECTOR_COMMIT_ID" : "65770ba03a8b839b9a4c9907a3eff2924db102bc", "PLATFORM_WHEN_CHALKED" : "GNU/Linux x86_64", "METADATA_ID" : "ECSG1B-Z42X-AZEM-T93DN8" }
