#!/bin/bash
# Get test tools from a container image. Do not install them on the host.
#
# Usage: image_tools.sh RUNTIME IMAGE TOOL_DIR [PIP_PACKAGE...]
#
# The script extracts the file system of IMAGE into TOOL_DIR. It installs the
# PIP_PACKAGEs with pip in a container, not on the host. For each console
# script of the packages, it writes a wrapper into TOOL_DIR/bin. The wrapper
# runs the script on the host with the Python, the loader and the libraries of
# the image. Thus the test uses the tools of the image, but it sees the files,
# the users and the commands of the host.
#
# Add TOOL_DIR/bin to PATH to use the wrappers. Remove TOOL_DIR to remove the
# tools.

set -euo pipefail

if (($# < 3)); then
    echo "Usage: $0 RUNTIME IMAGE TOOL_DIR [PIP_PACKAGE...]" >&2
    exit 1
fi

runtime=$1
image=$2
tool_dir=$3
shift 3

rm -rf "$tool_dir"
mkdir -p "$tool_dir/bin" "$tool_dir/opt/site"

cid=$("$runtime" create "$image")
trap '"$runtime" rm -f "$cid" > /dev/null' EXIT
"$runtime" export "$cid" | tar -x -C "$tool_dir" --exclude='dev/*'

if (($#)); then
    "$runtime" run --rm -v "$tool_dir/opt:/opt:Z" "$image" \
        python3 -m pip install -q --root-user-action=ignore --target /opt/site "$@"
fi

# Resolve a symbolic link in tool_dir. An absolute target is relative to
# tool_dir, not to the root of the host.
resolve() {
    local path=$1 target
    while [[ -L $path ]]; do
        target=$(readlink "$path")
        if [[ $target == /* ]]; then
            path=$tool_dir$target
        else
            path=$(dirname "$path")/$target
        fi
    done
    echo "$path"
}

loader=
for name in lib64/ld-linux-x86-64.so.2 lib/ld-linux-aarch64.so.1 lib/ld64.so.1 lib64/ld64.so.2; do
    if [[ -L $tool_dir/$name || -e $tool_dir/$name ]]; then
        loader=$(resolve "$tool_dir/$name")
        break
    fi
done
if [[ -z $loader ]]; then
    echo "Error: cannot find the dynamic loader in $image" >&2
    exit 1
fi

python=$(find "$tool_dir/usr/bin" -maxdepth 1 -regex '.*/python3\.[0-9]+' | sort -V | tail -n 1)
if [[ -z $python ]]; then
    echo "Error: cannot find Python in $image" >&2
    exit 1
fi
python=$(resolve "$python")
libs=$tool_dir/lib64:$tool_dir/usr/lib64:$tool_dir/lib:$tool_dir/usr/lib

# Python reads PYTHONHOME and PYTHONPATH at start. Then remove them, thus the
# commands that the test runs on the host do not use the Python of the image.
cat > "$tool_dir/opt/site/sitecustomize.py" << 'EOF'
import os

os.environ.pop("PYTHONHOME", None)
os.environ.pop("PYTHONPATH", None)
EOF

for script in "$tool_dir"/opt/site/bin/*; do
    [[ -f $script ]] || continue
    wrapper=$tool_dir/bin/${script##*/}
    cat > "$wrapper" << EOF
#!/bin/sh
PYTHONHOME='$tool_dir/usr' PYTHONPATH='$tool_dir/opt/site' exec '$loader' --library-path '$libs' '$python' '$script' "\$@"
EOF
    chmod +x "$wrapper"
done
