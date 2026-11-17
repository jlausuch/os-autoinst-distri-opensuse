#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
# Summary: Generic helper for openQA-agnostic tests
#
# Runs standalone test artifacts (Go/Python/Java/shell) both inside openQA
# and on a bare SUT. The 'domain' constructor arg controls which data/
# subtree test files are fetched from (e.g. 'security', 'console').
# The 'shell' language expects a self-contained runtest emitting TAP and
# installs no test framework, so it also works on minimal images.
#
# If AGNOSTIC_CONTAINER is set, the runner installs no test dependencies on
# the SUT. It installs only the container runtime, if it is not available.
# The runtest executes in that container image, which must contain the
# test framework (go and gotestsum, a JDK) and nsenter. If the image has no
# pytest, the runner installs it in a local copy of the image. The
# container is privileged, uses the host PID, network, IPC, UTS and cgroup
# namespaces and gets the host root file system at /host. HOST_ROOT=/host
# is set in the container. The host is the system under test, thus
# lib/agnostic_container.sh starts the runtest: it shows the host state
# directories (for example /etc, /root, /tmp) in the container and runs
# host commands in the host namespaces. Tests need no changes. For special
# cases, the on_host helper (lib/helper.sh) and lib/agnostic_host.py are
# available. CONTAINER_RUNTIMES selects the runtime (first entry, default
# podman).
#
# Maintainer: QE Core <qe-core@suse.de>

package agnosticTestRunner;

use strict;
use warnings;
use testapi qw(assert_script_run script_run data_url parse_extra_log script_output upload_logs record_info get_var);
use Mojo::DOM;
use registration 'add_suseconnect_product', 'get_addon_fullname';
use package_utils 'install_package';
use utils 'zypper_call';
use version_utils 'is_sle';
use containers::common qw(install_podman_when_needed install_docker_when_needed);

sub new {
    my ($class, $args) = @_;

    die "Constructor requires a hashref" unless ref($args) eq 'HASH';
    die "Attribute 'name' is mandatory" unless defined $args->{name};
    die "Attribute 'language' is mandatory" unless defined $args->{language};
    die "Unsupported language '$args->{language}'. Supported: go, python, java, shell"
      unless $args->{language} =~ /^(go|python|java|shell)$/;

    $args->{domain} //= 'security';
    $args->{test_dir} //= '~/' . $args->{name};
    my $is_tap = $args->{language} =~ /^(java|shell)$/;
    $args->{result_format} //= $is_tap ? 'TAP' : 'XUnit';
    $args->{result_file} //= '/tmp/' . lc($args->{name}) . ($is_tap ? '_results.tap' : '_results.xml');
    $args->{data_url_path} //= $args->{domain} . '/openqa_agnostic/' . $args->{language} . '/' . $args->{name};
    $args->{helper_path} //= 'openqa_agnostic/lib/helper.sh';
    $args->{host_helper_path} //= 'openqa_agnostic/lib/agnostic_host.py';
    $args->{container_entry_path} //= 'openqa_agnostic/lib/agnostic_container.sh';
    $args->{run_command} //= 'runtest';
    $args->{run_timeout} //= 90;
    $args->{skip_phub} //= 0;
    $args->{container_image} //= get_var('AGNOSTIC_CONTAINER');
    $args->{container_runtime} //= (split(/\s*,\s*/, get_var('CONTAINER_RUNTIMES', '')))[0] || 'podman';
    $args->{pull_timeout} //= 600;
    return bless $args, $class;
}

sub latest_java_devel {
    my $out = script_output(
        q{zypper --terse -n se  'java-*-openjdk-devel'},
        proceed_on_failure => 1);
    my @majors = sort { $a <=> $b } ($out =~ /\bjava-(\d+)-openjdk-devel\b/g);
    die 'No java-*-openjdk-devel package available in configured repos' unless @majors;
    return "java-$majors[-1]-openjdk-devel";
}

sub _python_version {
    my $out = script_output('python3 -c "import sys; print(sys.version_info[1])"',
        proceed_on_failure => 1, quiet => 1, timeout => 10);
    return ($out =~ /^(\d+)/) ? $1 + 0 : 0;
}

sub _install_python_deps {
    my ($self) = @_;
    return if script_run('python3 -m pytest --version', timeout => 10, quiet => 1) == 0;

    # python3-pytest from PackageHub requires python3-wcwidth, which on SLE 15
    # is shipped only in the Public Cloud Module. Activate it before installing;
    # on products without that module the dependency is in the regular
    # repositories, so a failure to activate it must not be fatal.
    if (is_sle('<16.0')) {
        eval { add_suseconnect_product(get_addon_fullname('pcm')) };
        record_info('pcm', "Could not activate the Public Cloud Module: $@") if $@;
        zypper_call('--gpg-auto-import-keys ref', retry_on_timeout => 1) unless $@;
    }

    eval { install_package('python3-pytest', trup_reboot => 1) };
    if ($@) {
        record_info('pkg fallback', "zypper cannot install python3-pytest, using pip3");
        install_package('python3-pip');
        my $pip_cmd = 'pip3 install pytest';
        $pip_cmd .= ' --break-system-packages' if _python_version() >= 12;
        assert_script_run($pip_cmd, timeout => 120);
    }
}

sub _setup_container {
    my ($self) = @_;
    my $runtime = $self->{container_runtime};
    my $image = $self->{container_image};
    if ($runtime eq 'podman') {
        install_podman_when_needed();
    } elsif ($runtime eq 'docker') {
        install_docker_when_needed();
    } else {
        die "Unsupported container runtime '$runtime'. Supported: podman, docker";
    }
    record_info('container', "Run $self->{name} in $image with $runtime");
    assert_script_run("$runtime pull $image", timeout => $self->{pull_timeout});
    $self->_container_install_pytest() if $self->{language} eq 'python';
}

# Install pytest in the container image if it is not available, for example
# in registry.suse.com/bci/python. Install it one time in a temporary
# container and commit the result to a local image, which all agnostic tests
# of the job then use. Use python3XY-pytest from the repositories and pip as
# fallback.
sub _container_install_pytest {
    my ($self) = @_;
    my $runtime = $self->{container_runtime};
    my $local_image = 'localhost/agnostic-pytest:latest';
    my $setup_name = 'agnostic-pytest-setup';

    if (script_run("$runtime image inspect $local_image > /dev/null 2>&1", quiet => 1) == 0) {
        $self->{container_image} = $local_image;
        return;
    }
    return if script_run("$runtime run --rm $self->{container_image} python3 -m pytest --version", timeout => 60) == 0;

    my $install = 'zypper -n in python$(python3 -c "import sys; print(sys.version_info[0] * 100 + sys.version_info[1])")-pytest'
      . ' || pip3 install pytest';
    script_run("$runtime rm -f $setup_name", quiet => 1);
    assert_script_run("$runtime run --name $setup_name $self->{container_image} sh -c '$install'", timeout => 300);
    assert_script_run("$runtime commit $setup_name $local_image && $runtime rm $setup_name", timeout => 120);
    $self->{container_image} = $local_image;
}

sub setup {
    my ($self) = @_;
    my $url = data_url($self->{data_url_path});

    # In container mode the image brings the tooling and the shell language
    # brings its own tooling, so no test framework is installed.
    if ($self->{container_image}) {
        $self->_setup_container();
    } elsif ($self->{language} ne 'shell') {
        if ($self->{language} eq 'python') {
            # Version check before PackageHub to avoid wasting 30-60s
            my $minor = _python_version();
            if ($minor < 6) {
                record_info('skip', "Python 3.$minor < 3.6, skipping agnostic test");
                $self->{skipped} = 1;
                return $self;
            }
        }

        if (!$self->{skip_phub} && is_sle('<16.0')) {
            add_suseconnect_product(get_addon_fullname('phub'));
            zypper_call('--gpg-auto-import-keys ref', retry_on_timeout => 1);
        }

        if ($self->{language} eq 'python') {
            $self->_install_python_deps();
        } elsif ($self->{language} eq 'go') {
            install_package('go gotestsum', trup_reboot => 1);
        } elsif ($self->{language} eq 'java') {
            install_package(latest_java_devel(), trup_reboot => 1);
        }
    }

    # Create test_dir and sibling lib/ for shared helpers in one shot
    my $test_dir = $self->{test_dir};
    assert_script_run("mkdir -p $test_dir/../lib", quiet => 1);
    my $helper_url = data_url($self->{helper_path});
    assert_script_run("curl -s -o $test_dir/../lib/helper.sh $helper_url", quiet => 1);
    my $host_helper_url = data_url($self->{host_helper_path});
    assert_script_run("curl -s -o $test_dir/../lib/agnostic_host.py $host_helper_url", quiet => 1);
    if ($self->{container_image}) {
        my $entry_url = data_url($self->{container_entry_path});
        assert_script_run("curl -s -o $test_dir/../lib/agnostic_container.sh $entry_url", quiet => 1);
    }

    # Download and discover test files via runtest -f
    my $run_script = $self->{run_command};
    assert_script_run("curl -s -o $test_dir/$run_script $url/$run_script", quiet => 1);
    assert_script_run("chmod +x $test_dir/$run_script", quiet => 1);

    my $file_list_output = script_output("cd $test_dir && ./$run_script -f", quiet => 1);
    $file_list_output =~ s/^\s+|\s+$//g;
    if ($file_list_output) {
        my @files = split(/\s+/, $file_list_output);
        assert_script_run("cd $test_dir && curl -s " . join(' ', map { "-O $url/$_" } @files), quiet => 1) if @files;
    }

    return $self;
}

# Return the prefix that runs the runtest in the container. The host root
# is at /host. lib/agnostic_container.sh prepares the container and starts
# the runtest in the test directory of the host, thus the runtest writes
# results.* directly to the host.
sub _container_prefix {
    my ($self, $env) = @_;
    my @cmd = ($self->{container_runtime}, 'run --rm --privileged',
        '--pid=host --network=host --ipc=host --uts=host --cgroupns=host',
        '-v /:/host -e HOST_ROOT=/host -w "/host$PWD"');
    push @cmd, "-e $env" if $env;
    return join(' ', @cmd, $self->{container_image}, 'bash ../lib/agnostic_container.sh "$PWD"', '');
}

sub run_test {
    my ($self) = @_;
    return $self if $self->{skipped};
    my $run_script = $self->{run_command};
    $run_script = "./$run_script" unless $run_script =~ m{^/|^\./};
    my $result_src = $self->{result_format} eq 'TAP' ? 'results.tap' : 'results.xml';
    my $name = $self->{name};
    my $output_log = "/tmp/${name}_output.log";
    # openQA identifies XUnit results by the testsuite name. The default
    # pytest name is 'pytest', thus two agnostic tests in one job collide and
    # one of them can stay without a result. Set a unique name for each test.
    my $env = $self->{language} eq 'python' ? "PYTEST_ADDOPTS='-o junit_suite_name=${name}_pytest'" : '';
    my $exec = $self->{container_image} ? $self->_container_prefix($env) . $run_script
      : ($env ? "$env " : '') . $run_script;
    my $command = 'cd ' . $self->{test_dir} . ' && chmod +x ' . $run_script
      . ' && ( set -o pipefail; ' . $exec . " 2>&1 | tee $output_log )"
      . ' && mv ' . $result_src . ' ' . $self->{result_file};
    assert_script_run($command, timeout => $self->{run_timeout}, quiet => 1);
    upload_logs($output_log, failok => 1);
    script_run('reset');
    return $self;
}

sub parse_results {
    my ($self) = @_;
    return $self if $self->{skipped};
    parse_extra_log($self->{result_format}, $self->{result_file});

    my $content = script_output('cat ' . $self->{result_file}, quiet => 1);
    my $has_failures = 0;

    if ($self->{result_format} eq 'TAP') {
        for my $line (split /\n/, $content) {
            if ($line =~ /^ok\s+\d+\s*-?\s*(.*)/) {
                record_info("PASSED: $1", '', result => 'ok');
            } elsif ($line =~ /^not ok\s+\d+\s*-?\s*(.*)/) {
                $has_failures = 1;
                record_info("FAILED: $1", $line, result => 'fail');
            }
        }
    } else {
        my $dom = Mojo::DOM->new->xml(1)->parse($content);
        for my $tc ($dom->find('testcase')->each) {
            my $name = $tc->{name};
            my $failure = $tc->at('failure');
            my $error = $tc->at('error');
            my $skipped = $tc->at('skipped');
            if ($failure || $error) {
                $has_failures = 1;
                my $node = $failure || $error;
                my $msg = $node->{message} || $node->text || '';
                record_info("FAILED: $name", $msg, result => 'fail');
            } elsif ($skipped) {
                my $msg = $skipped->{message} || '';
                record_info("SKIPPED: $name", $msg, result => 'ok');
            } else {
                record_info("PASSED: $name", '', result => 'ok');
            }
        }
    }

    if ($has_failures) {
        $autotest::current_test->{result} = 'fail';
    }
    return $self;
}

sub cleanup {
    my ($self) = @_;
    assert_script_run('cd ~ && rm -rf ' . $self->{test_dir}, quiet => 1) unless $self->{skipped};
    return $self;
}

1;
