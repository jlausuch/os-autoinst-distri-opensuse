#!/bin/bash
# Entry point for agnostic tests in a container (AGNOSTIC_CONTAINER).
#
# The host is the system under test. This script prepares the container
# so that an unchanged runtest operates on the host:
#   - Host directories with state (/etc, /usr/etc, /root, /home, /tmp,
#     /var, /run, /srv, /opt) replace the container directories. Host
#     files in /usr that the host /etc links to replace the container files.
#   - Each host command replaces the container command with a wrapper
#     that executes the host command in the host namespaces (nsenter).
#     The test framework commands (shell, Python, pytest, Go, Java, the
#     compiler) stay in the container.
# The mounts and wrappers exist only in the container. The host does not
# change.
#
# Usage:
#   agnostic_container.sh <host_work_dir> <command> [<argument>...]
#
# The container must be privileged, use the host PID namespace and have
# the host root file system at HOST_ROOT (default /host).

set -e

HOST_ROOT=${HOST_ROOT:-/host}
work_dir=$1
shift

state_dirs=(etc usr/etc root home tmp var run srv opt)
bin_dirs=(usr/bin usr/sbin bin sbin)
stage=/.agnostic
nsenter_bin=$(command -v nsenter)

# Return 0 if the command must stay in the container.
keep_in_container() {
    case "$1" in
        sh | bash | dash | env | nsenter | mount | umount) return 0 ;;
        python | python3 | python3.* | pip | pip3 | pip3.* | pytest | pytest-* | py.test*) return 0 ;;
        go | gofmt | gotestsum | java | javac | jar | jshell | keytool) return 0 ;;
        cc | c++ | gcc | gcc-* | g++ | g++-* | cpp | cpp-* | ld | ld.* | as | ar | git) return 0 ;;
    esac
    return 1
}

# 1. Replace links to /etc/alternatives in the container with links to
#    the final target, because the host /etc replaces the container /etc.
for dir in "${bin_dirs[@]}" usr/local/bin; do
    [[ -d /$dir && ! -L /$dir ]] || continue
    for link in /"$dir"/*; do
        [[ -L $link && $(readlink "$link") == /etc/alternatives/* ]] || continue
        target=$(readlink -f "$link") || continue
        [[ -e $target ]] && ln -sfn "$target" "$link"
    done
done

# 2. Make a wrapper for each host command. The wrapper changes to the
#    same work directory on the host, if it is available.
for dir in "${bin_dirs[@]}"; do
    [[ -d $HOST_ROOT/$dir && ! -L $HOST_ROOT/$dir ]] || continue
    [[ -d /$dir && ! -L /$dir ]] || continue
    mkdir -p "$stage/$dir"
    for cmd in "$HOST_ROOT/$dir"/*; do
        name=${cmd##*/}
        [[ -L $cmd || (-f $cmd && -x $cmd) ]] || continue
        keep_in_container "$name" && continue
        printf '#!/bin/sh\nexec %s -t 1 -m -u -i -n -p -- /bin/sh -c '\''cd "$0" 2>/dev/null || cd /; exec "$@"'\'' "$PWD" %s "$@"\n' \
            "$nsenter_bin" "/$dir/$name" > "$stage/$dir/$name"
    done
    chmod 755 "$stage/$dir"/* 2> /dev/null || true
done

# 3. Keep the dynamic linker cache of the container for the test framework.
#    Keep cp, because step 5 replaces it with a wrapper.
cp /etc/ld.so.cache "$stage/ld.so.cache" 2> /dev/null || true
cp "$(command -v cp)" "$stage/cp"

# 4. Replace the container state directories with the host directories.
for dir in "${state_dirs[@]}"; do
    [[ -d $HOST_ROOT/$dir ]] || continue
    mkdir -p "/$dir"
    mount --rbind "$HOST_ROOT/$dir" "/$dir"
done
if [[ -f $stage/ld.so.cache && -f /etc/ld.so.cache ]]; then
    mount --bind "$stage/ld.so.cache" /etc/ld.so.cache
fi

# Links in the host /etc can point to files in the host /usr, for example
# /etc/os-release to /usr/lib/os-release. Use the host file for each such
# link, but not for commands (step 5 does this) and libraries.
"$nsenter_bin" -t 1 -m -- find /etc -type l -exec readlink -f {} + 2> /dev/null | sort -u |
    while IFS= read -r path; do
        case "$path" in
            /usr/bin/* | /usr/sbin/* | /usr/lib64/* | /usr/libexec/* | /usr/lib/*-linux-gnu/* | *.so | *.so.*) continue ;;
            /usr/*) ;;
            *) continue ;;
        esac
        [[ -f $HOST_ROOT$path && ! -L $HOST_ROOT$path ]] || continue
        mkdir -p "${path%/*}"
        [[ -e $path ]] || : > "$path"
        mount --bind "$HOST_ROOT$path" "$path"
    done

# 5. Install the wrappers. Remove the destination first, thus a link to a
#    kept command (for example rbash to bash) does not change that command.
for dir in "${bin_dirs[@]}"; do
    [[ -d $stage/$dir ]] || continue
    "$stage/cp" --remove-destination "$stage/$dir"/* "/$dir/"
done

cd "$work_dir" 2> /dev/null || cd "$HOST_ROOT$work_dir"
exec "$@"
