# SUSE's openQA tests
#
# Copyright 2023 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Tests a conainer image on an OpenShift cluster
#
# Maintainer: qa-c team <qa-c@suse.de>

use Mojo::Base qw(consoletest);
use testapi;
use serial_terminal 'select_serial_terminal';

sub run {
    select_serial_terminal;
    my $image = get_required_var('CONTAINER_IMAGE_TO_TEST');
    my $cmd = '"cat", "/etc/os-release"';
    my $job_name = "test";

    select_console "user-console";

    # Login to the deployment
    assert_script_run('eval $(crc oc-env)');
    assert_script_run('oc login -u developer https://api.crc.testing:6443');

    # Create kubernetes cluster from manifest
    assert_script_run("curl -O " . data_url("containers/k8s_job_manifest.yaml"));
    file_content_replace("k8s_job_manifest.yaml", JOB_NAME => $job_name, IMAGE => $image, CMD => $cmd);
    assert_script_run("oc create -f k8s_job_manifest.yaml", timeout => 600);

    # Various OpenShift operations with the image
    assert_script_run("oc import-image $image");
}

1;
