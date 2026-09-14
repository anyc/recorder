#!/bin/sh
set -eu

usage()
{
	cat <<'EOF'
Usage: scripts/container-build.sh [--test]

Build the librecorder container and compile the current checkout in it.

Options:
  --test    Run the complete test target after building.

Environment:
  CONTAINER_ENGINE  Set to podman or docker (auto-detected otherwise).
  IMAGE_NAME        Image tag (default: librecorder-build).
EOF
}

run_tests=0
while [ "$#" -gt 0 ]; do
	case "$1" in
		--test|--tests)
			run_tests=1
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "container-build: unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
	shift
done

engine=${CONTAINER_ENGINE:-}
if [ -z "$engine" ]; then
	if command -v podman >/dev/null 2>&1; then
		engine=podman
	elif command -v docker >/dev/null 2>&1; then
		engine=docker
	else
		echo "container-build: neither podman nor docker is installed" >&2
		exit 1
	fi
fi

case "$engine" in
	podman|docker)
		if ! command -v "$engine" >/dev/null 2>&1; then
			echo "container-build: requested engine not found: $engine" >&2
			exit 1
		fi
		;;
	*)
		echo "container-build: CONTAINER_ENGINE must be podman or docker" >&2
		exit 2
		;;
esac

image_name=${IMAGE_NAME:-librecorder-build}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

echo "container-build: building $image_name with $engine"
"$engine" build --pull=false -f "$repo_dir/Dockerfile" -t "$image_name" "$repo_dir"

echo "container-build: building librecorder"
volume_suffix=
if [ "$engine" = podman ]; then
	# Relabel the bind mount when Podman is running with SELinux enabled.
	volume_suffix=:Z
fi
if [ "$run_tests" -eq 1 ]; then
	"$engine" run --rm -v "$repo_dir:/workspace$volume_suffix" "$image_name" sh -c 'make -B test'
else
	"$engine" run --rm -v "$repo_dir:/workspace$volume_suffix" "$image_name" make repo
fi
