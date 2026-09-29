#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
check_dir=$(mktemp -d)
trap 'rm -rf "$check_dir"' EXIT
check_sdk=${ANDROID_HOME:-}
if [[ -z "$check_sdk" && -f local.properties ]]; then
  check_sdk=$(sed -n 's/^sdk.dir=//p' local.properties)
fi
check_platform="$check_sdk/platforms/android-37.0/android.jar"
if [[ ! -f "$check_platform" ]]; then
  check_platform="$check_sdk/platforms/android-37/android.jar"
fi
if [[ ! -f "$check_platform" ]]; then
  printf '%s\n' 'Set ANDROID_HOME or local.properties to an SDK with platform 37.' >&2
  exit 1
fi
timeout 30 javac -Xlint:all -Werror -classpath "$check_platform" -d "$check_dir" \
  app/src/main/java/at/farfeleder/localupload/RunState.java tests/RunStateCheck.java \
  app/src/main/java/at/farfeleder/localupload/ActivityLog.java tests/ActivityLogCheck.java \
  app/src/main/java/at/farfeleder/localupload/SafStorage.java \
  app/src/test/java/at/farfeleder/localupload/SafStoragePathCheck.java
timeout 30 java -ea -cp "$check_dir" at.farfeleder.localupload.RunStateCheck
timeout 30 java -ea -cp "$check_dir" at.farfeleder.localupload.ActivityLogCheck
timeout 30 java -ea -cp "$check_dir:$check_platform" at.farfeleder.localupload.SafStoragePathCheck
