#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
# Summary: Generic helper for openQA-agnostic tests
#
# Runs standalone test artifacts (Go/Python/Java/shell) both inside openQA
# and on a bare SUT. The 'domain' constructor arg controls which data/
# subtree test files are fetched from (e.g. 'security', 'console').
# The 'shell' language expects a self-contained runtest emitting TAP.
# Inside openQA, the test framework comes from a container image and is
# extracted to a temporary directory (see data/openqa_agnostic/lib/image_tools.sh).
# The test runs on the SUT with these tools, so nothing is installed on the SUT
# except the container runtime.
#
# Maintainer: QE Core <qe-core@suse.de>

package agnosticTestRunner;

use strict;
use warnings;
use testapi qw(assert_script_run script_run data_url parse_extra_log script_output upload_logs record_info get_var);
use Mojo::DOM;
use containers::common qw(install_docker_when_needed install_podman_when_needed);

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
    $args->{run_command} //= 'runtest';
    $args->{run_timeout} //= 90;
    # The test framework always comes from this image
    $args->{container_image} ||= 'registry.suse.com/bci/python:3.13';
    # Use podman if it is the first runtime in CONTAINER_RUNTIMES, else use docker
    my ($runtime) = get_var('CONTAINER_RUNTIMES', '') =~ /^\s*([^,\s]*)/;
    $args->{container_runtime} //= ($runtime // '') eq 'podman' ? 'podman' : 'docker';
    $args->{tool_dir} //= '/var/tmp/' . lc($args->{name}) . '_tools';
    $args->{tools_path} //= 'openqa_agnostic/lib/image_tools.sh';
    return bless $args, $class;
}

sub setup {
    my ($self) = @_;
    my $url = data_url($self->{data_url_path});

    # The container image brings the test framework, so only the container runtime is needed
    my $runtime = $self->{container_runtime};
    $runtime eq 'podman' ? install_podman_when_needed() : install_docker_when_needed();
    assert_script_run("$runtime pull $self->{container_image}", timeout => 600);

    # Create test_dir and sibling lib/ for shared helpers in one shot
    my $test_dir = $self->{test_dir};
    assert_script_run("mkdir -p $test_dir/../lib", quiet => 1);
    my $helper_url = data_url($self->{helper_path});
    assert_script_run("curl -s -o $test_dir/../lib/helper.sh $helper_url", quiet => 1);

    # Extract the test framework from the image to tool_dir
    my $tools_url = data_url($self->{tools_path});
    assert_script_run("curl -s -o $test_dir/../lib/image_tools.sh $tools_url", quiet => 1);
    my $pip_packages = $self->{language} eq 'python' ? 'pytest' : '';
    assert_script_run("bash $test_dir/../lib/image_tools.sh $runtime $self->{container_image} $self->{tool_dir} $pip_packages",
        timeout => 600);

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

sub run_test {
    my ($self) = @_;
    my $run_script = $self->{run_command};
    $run_script = "./$run_script" unless $run_script =~ m{^/|^\./};
    my $result_src = $self->{result_format} eq 'TAP' ? 'results.tap' : 'results.xml';
    my $name = $self->{name};
    my $output_log = "/tmp/${name}_output.log";
    # openQA identifies XUnit results by the testsuite name. The default
    # pytest name is 'pytest', thus two agnostic tests in one job collide and
    # one of them can stay without a result. Set a unique name for each test.
    my $env = $self->{language} eq 'python' ? "PYTEST_ADDOPTS='-o junit_suite_name=${name}_pytest' " : '';
    # Run the test on the host. The wrappers in tool_dir/bin come first in PATH.
    my $command = 'cd ' . $self->{test_dir} . ' && chmod +x ' . $run_script
      . " && ( set -o pipefail; PATH=$self->{tool_dir}/bin:\$PATH " . $env . $run_script . " 2>&1 | tee $output_log )"
      . ' && mv ' . $result_src . ' ' . $self->{result_file};
    assert_script_run($command, timeout => $self->{run_timeout}, quiet => 1);
    upload_logs($output_log, failok => 1);
    script_run('reset');
    return $self;
}

sub parse_results {
    my ($self) = @_;
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
    assert_script_run('cd ~ && rm -rf ' . $self->{test_dir} . ' ' . $self->{tool_dir}, quiet => 1);
    return $self;
}

1;
