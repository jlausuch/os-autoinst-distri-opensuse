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

    my $cmd = "podman exec sut sh -c 'GNUTLS_FORCE_FIPS_MODE=1 gnutls-cli --fips140-mode' 2>&1";
    validate_script_output($cmd, sub { m/library is in FIPS140-3 mode|library is in FIPS140-2 mode|library is in FIPS140 mode/ });
}

sub test_flags {
    return {milestone => 0, fatal => 0, no_rollback => 1}
}

1;
