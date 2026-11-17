"""Access the host, which is the system under test, from agnostic tests.

In container mode the runner sets HOST_ROOT to the mount point of the host
root file system. Commands then run in the namespaces of the host init
process. Without HOST_ROOT the test runs on the host and the helpers do
nothing special.

Usage:
    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
    from agnostic_host import run_on_host, host_path

    run_on_host(['useradd', '-m', 'testuser'])
    with open(host_path('/etc/group')) as f:
        ...
"""

import os
import subprocess

HOST_ROOT = os.environ.get('HOST_ROOT', '')
NSENTER = ['nsenter', '-t', '1', '-m', '-u', '-i', '-n', '-p', '--']


def in_container():
    """Return True if the test runs in the agnostic container."""
    return bool(HOST_ROOT)


def host_cmd(cmd):
    """Return cmd (list or shell string) prefixed to run on the host."""
    if not in_container():
        return cmd
    if isinstance(cmd, str):
        return NSENTER + ['/bin/sh', '-c', cmd]
    return NSENTER + list(cmd)


def run_on_host(cmd, **kwargs):
    """Run cmd on the host. Accept the same arguments as subprocess.run."""
    if kwargs.pop('shell', False) and not in_container():
        return subprocess.run(cmd, shell=True, **kwargs)
    return subprocess.run(host_cmd(cmd), **kwargs)


def host_path(path):
    """Return the path of a host file as the test sees it."""
    return HOST_ROOT + path if in_container() else path
