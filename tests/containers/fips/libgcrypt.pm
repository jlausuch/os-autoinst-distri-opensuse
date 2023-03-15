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

    # dirmngr is needed by gpgconf
    assert_script_run("podman exec sut sh -c 'zypper in -y dirmngr'");

    my $cmd = "podman exec sut sh -c 'LIBGCRYPT_FORCE_FIPS_MODE=1 gpgconf --show-versions | grep -i fips'";
    validate_script_output($cmd, sub { m/^fips-mode:y::Libgcrypt version/ });

    # Should show no version
    $cmd = "podman exec sut sh -c 'gpgconf --show-versions | grep -i fips'";
    validate_script_output($cmd, sub { m/^fips-mode:y::Libgcrypt version/ });
}

sub test_flags {
    return {milestone => 0, fatal => 0, no_rollback => 1}
}

1;
