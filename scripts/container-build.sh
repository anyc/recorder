#!/bin/sh
set -eu

usage()
{
	cat <<'EOF'
Usage: scripts/container-build.sh [--test] [--journal] [--console]

Build the librecorder container and compile the current checkout in it.

Options:
  --test    Run the complete test target after building.
  --journal Mount the host's systemd journal read-only in the container.
  --console Enter an interactive shell after preparing the checkout.

Environment:
  CONTAINER_ENGINE  Set to podman or docker (auto-detected otherwise).
  IMAGE_NAME        Image tag (default: librecorder-build).
EOF
}

run_tests=0
journal_access=0
console_mode=0
while [ "$#" -gt 0 ]; do
	case "$1" in
		--test|--tests)
			run_tests=1
			;;
		--journal|--host-journal)
			journal_access=1
			;;
		--console)
			console_mode=1
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

if [ "$console_mode" -eq 1 ] && [ "$run_tests" -eq 1 ]; then
	echo "container-build: --console cannot be combined with --test" >&2
	exit 2
fi

if [ "$journal_access" -eq 1 ]; then
	for journal_path in /run/log/journal /var/log/journal /etc/machine-id; do
		if [ ! -e "$journal_path" ]; then
			echo "container-build: host journal path is unavailable: $journal_path" >&2
			exit 1
		fi
	done
fi

echo "container-build: building $image_name with $engine"
"$engine" build --pull=false -f "$repo_dir/Dockerfile" -t "$image_name" "$repo_dir"

echo "container-build: building librecorder"
volume_suffix=
if [ "$engine" = podman ]; then
	# Relabel the bind mount when Podman is running with SELinux enabled.
	volume_suffix=:Z
fi
run_build='created_flatcc=0
if [ ! -e flatcc ]; then
    ln -s /opt/flatcc-src flatcc
    created_flatcc=1
fi
cleanup()
{
    if [ "$created_flatcc" -eq 1 ]; then
        rm -f flatcc
    fi
}
trap cleanup EXIT
export LD_LIBRARY_PATH=/workspace
make -B'

interactive_flags=
if [ "$console_mode" -eq 1 ]; then
	interactive_flags=-it
fi

container_run()
{
	if [ "$journal_access" -eq 1 ]; then
		if [ "$engine" = podman ]; then
			"$engine" run --rm $interactive_flags --security-opt label=disable \
				-v "$repo_dir:/workspace$volume_suffix" \
				-v /run/log/journal:/run/log/journal:ro \
				-v /var/log/journal:/var/log/journal:ro \
				-v /etc/machine-id:/etc/machine-id:ro \
				"$image_name" "$@"
		else
			"$engine" run --rm $interactive_flags \
				-v "$repo_dir:/workspace$volume_suffix" \
				-v /run/log/journal:/run/log/journal:ro \
				-v /var/log/journal:/var/log/journal:ro \
				-v /etc/machine-id:/etc/machine-id:ro \
				"$image_name" "$@"
		fi
	else
		"$engine" run --rm $interactive_flags -v "$repo_dir:/workspace$volume_suffix" "$image_name" "$@"
	fi
}

if [ "$console_mode" -eq 1 ]; then
	console_message='cat <<"INFO"
librecorder development container

Available commands:
  make repo       Build recorder, player, and librecorder
  make -B test    Rebuild and run the complete test suite
  flatcc --help   Show the FlatCC schema compiler help
  exit            Leave the container
INFO
exec /bin/sh'
	container_run sh -c "${run_build%make -B}$console_message"
elif [ "$run_tests" -eq 1 ]; then
	container_run sh -c "$run_build test"
else
	container_run sh -c "$run_build repo"
fi
