# SUSE's openQA tests
#
# Copyright 2023 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Summary: https://confluence.suse.com/display/FIPS/FIPS-140-3-SLE15-SP4+Vendor+affirmation
# Maintainer: qa-c team <qa-c@suse.de>


use Mojo::Base qw(opensusebasetest);
use testapi;
use serial_terminal 'select_serial_terminal';
use utils qw(zypper_call);
use Utils::Architectures qw(is_s390x);

sub run {
    my ($self, $args) = @_;
    select_serial_terminal;

    my $image = get_var('IMAGE_UNDER_TEST', 'registry.suse.com/bci/bci-base:15.4');

    # Make sure Host is FIPS enabled
    record_info('kernel cmdline', script_output('cat /proc/cmdline'));
    assert_script_run("grep '^1\$' /proc/sys/crypto/fips_enabled");
    record_info('INFO', 'FIPS is enabled on the Host.');

    # Install podman in the host if not installed
    zypper_call('in podman');
    record_info("podman", script_output('podman -v'));

    # Pull image
    assert_script_run("podman pull $image");
    record_info("image", "$image" . script_output("podman image inspect $image"));

    # Run container and leave it running
    assert_script_run("podman run -dt --name sut $image bash");
    validate_script_output('podman ps', sub { m/sut/ });

    record_info("os-release", script_output('podman exec sut cat /etc/os-release'));

    # Install NSS package from specific repo
    my $nss_repo = 'http://download.suse.de/ibs/Devel:/Desktop:/Mozilla:/SLE-15:/next/standard/';
    assert_script_run("podman exec sut sh -c 'zypper ar $nss_repo nss_repo'");
    assert_script_run("podman exec sut sh -c 'zypper --gpg-auto-import-keys ref'", timeout => 300);
    assert_script_run("podman exec sut sh -c 'zypper in -y --from nss_repo mozilla-nss mozilla-nss-tools'");

    # Install (if needed) packages
    my $packages = 'libopenssl1_1 libopenssl1_1 gnutls libgnutls30 libgnutls30-hmac libnettle8 libgcrypt20 libgcrypt20-hmac';
    $packages .= ' libica4 libica-tools' if is_s390x;
    assert_script_run("podman exec sut sh -c 'zypper in -y $packages'");
    record_info('VERSIONS', script_output("podman exec sut sh -c 'rpm -q $packages'"));
}

sub test_flags {
    return {fatal => 1, milestone => 1};
}

1;
