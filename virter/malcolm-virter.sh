#!/usr/bin/env bash

set -o pipefail
set -u
shopt -s nocasematch
ENCODING="utf-8"

SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

REPO_OWNER=idaholab
REPO_NAME=Malcolm
REPO_BRANCH=main
GITHUB_TOKEN=${GITHUB_TOKEN:-}

CPU=${QEMU_CPU:-4}
RAM=${QEMU_RAM:-16384}
DISK=${QEMU_DISK:-50G}

IMAGE=${QEMU_IMAGE:-debian-12}
IMAGE_USER=${QEMU_USER:-debian}

VM_ID=$((120 + $RANDOM % 80))
VM_NAME="malcolm-${VM_ID}"
RM_AFTER_EXEC=

while getopts 'rvo:b:c:m:d:i:u:n:g:' OPTION; do
  case "$OPTION" in

    r)
      RM_AFTER_EXEC=0
      ;;

    v)
      set -x
      ;;

    o)
      REPO_OWNER="$OPTARG"
      ;;

    b)
      REPO_BRANCH="$OPTARG"
      ;;

    g)
      GITHUB_TOKEN="$OPTARG"
      ;;

    c)
      CPU="$OPTARG"
      ;;

    m)
      RAM="$OPTARG"
      ;;

    d)
      DISK="$OPTARG"
      ;;

    i)
      IMAGE="$OPTARG"
      ;;

    n)
      VM_NAME="$OPTARG"
      ;;

    u)
      IMAGE_USER="$OPTARG"
      ;;

    ?)
      echo -e "\nscript usage: $(basename $0) OPTIONS"
      echo -e "Options:\n\t[-v (verbose)]\n\t[-c <CPUs>]\n\t[-m <RAM mebibytes>]\n\t[-d <disk size and units>]\n\t[-i <image name>]\n\t[-n <VM name>]\n\t[-u <default user>]\n\t[-o <Malcolm repo owner>]\n\t[-b <Malcolm repo branch>]\n\t[-g <GitHub token>]\n\t[-r (remove VM upon completion)]\n" >&2
      exit 1
      ;;

  esac
done
shift "$(($OPTIND -1))"

unset SSH_AUTH_SOCK

virter vm run "${IMAGE}" \
  --id ${VM_ID} \
  --name "${VM_NAME}" \
  --vcpus ${CPU} \
  --memory ${RAM}MiB \
  --bootcapacity "${DISK}" \
  --user "${IMAGE_USER}" \
  --wait-ssh \
  "$@"

pushd "$SCRIPT_PATH" >/dev/null 2>&1
for SETUPFILE in malcolm-setup*.toml; do
    virter vm exec "${VM_NAME}" \
      --set "env.REPO_OWNER=$REPO_OWNER" \
      --set "env.REPO_BRANCH=$REPO_BRANCH" \
      --set "env.REPO_NAME=$REPO_NAME" \
      --set "env.GITHUB_TOKEN=$GITHUB_TOKEN" \
      --provision "${SETUPFILE}"
done
popd >/dev/null 2>&1

[[ -n "$RM_AFTER_EXEC" ]] && virter vm rm "${VM_NAME}"
