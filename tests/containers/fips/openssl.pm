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

    # This command should fail
    my $cmd = 'OPENSSL_FIPS=1 openssl md5 /etc/passwd';
    record_info('md5', $cmd);
    script_run("podman exec sut sh -c '$cmd'") != 0 or die("$cmd works, MD5 should fail on FIPS.");

    # This command should work
    my $cmd = 'OPENSSL_FIPS=1 openssl sha512 /etc/passwd';
    record_info('sha512', $cmd);
    assert_script_run("podman exec sut sh -c 'OPENSSL_FIPS=1 openssl sha512 /etc/passwd'");
}

sub test_flags {
    return {milestone => 0, fatal => 0, no_rollback => 1}
}

1;
