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

    my $details = "\"CN=Daniel Duesentrieb3,O=Example Corp,L=Mountain View,ST=California,C=DE\" -d /root/nssdb -o /root/cert9.cer -f /root/password.txt -z /root/seedfile.dat";

    assert_script_run("podman exec sut sh -c 'cat /dev/urandom | head -n 120 > /root/seedfile.dat'");
    assert_script_run("podman exec sut sh -c 'touch /root/password.txt'");
    assert_script_run("podman exec sut sh -c 'mkdir -p /root/nssdb'");
    assert_script_run("podman exec sut sh -c 'certutil -N -d /root/nssdb --empty-password'");
    script_run("podman exec sut sh -c 'modutil -force -fips true -dbdir /root/nssdb'");

    # 1024 keys not allowed in FIPS, this is expected to fail
    record_info('1024', '-g 1024 expected to fail on FIPS');
    validate_script_output("podman exec sut sh -c 'export NSS_FIPS=1 && certutil -R -k rsa -g 1024 -s $details' 2>&1", sub { m/SEC_ERROR_INVALID_ARGS/ }, proceed_on_failure => 1, timeout => 300);

    # This should work
    record_info('2048', '-g 1024 expected to work on FIPS');
    assert_script_run("podman exec sut sh -c 'export NSS_FIPS=1 && certutil -R -k rsa -g 2048 -s $details'");
}

sub test_flags {
    return {milestone => 0, fatal => 0, no_rollback => 1}
}

1;
