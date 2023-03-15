# SUSE's openQA tests
#
# Copyright 2023 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Summary: https://confluence.suse.com/display/FIPS/FIPS-140-3-SLE15-SP4+Vendor+affirmation
# Maintainer: qa-c team <qa-c@suse.de>


use Mojo::Base qw(opensusebasetest);
use testapi;
use serial_terminal 'select_serial_terminal';

sub run {
    my ($self, $args) = @_;
    select_serial_terminal;
    record_info('icainfo', script_output("podman exec sut sh -c 'icainfo'"));
    record_info('-f', script_output("podman exec sut sh -c 'icainfo -f'"));
    record_info('-v', script_output("podman exec sut sh -c 'icainfo -v'"));
    validate_script_output("podman exec sut sh -c 'icainfo'", sub { m/FIPS 140-3 mode active/ });
}

sub test_flags {
    return {milestone => 0, fatal => 0, no_rollback => 1}
}

1;
