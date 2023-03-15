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

    # Install openJDK 11
    assert_script_run("podman exec sut sh -c 'zypper in -y java-11-openjdk java-11-openjdk-devel git-core wget'");

    # Configure nssdb
    assert_script_run("podman exec sut sh -c 'mkdir /etc/pki/nssdb'");
    assert_script_run("podman exec sut sh -c 'certutil -N -d /etc/pki/nssdb --empty-password'");
    assert_script_run("podman exec sut sh -c 'chmod og+r /etc/pki/nssdb/*'");

    # Simple java crypto test
    assert_script_run("podman exec sut sh -c 'cd /root;git clone -q https://github.com/ecki/JavaCryptoTest'");
    assert_script_run("podman exec sut sh -c 'javac /root/JavaCryptoTest/src/main/java/net/eckenfels/test/jce/JCEProviderInfo.java'");
    my $crypto = script_output("podman exec sut sh -c 'java -cp /root/JavaCryptoTest/src/main/java/ net.eckenfels.test.jce.JCEProviderInfo'");
    record_info("FAIL", "Cannot list all crypto providers", result => 'fail') if ($crypto !~ /Listing all JCA Security Providers/);

    # Prepare testing data
    my $JDK_TCHECK = get_var("JDK_TCHECK", "https://gitlab.suse.de/qe-security/testing/-/raw/main/data/openjdk/Tcheck.java");
    assert_script_run("podman exec sut sh -c 'wget --quiet --no-check-certificate $JDK_TCHECK'");
    assert_script_run("podman exec sut sh -c 'chmod 777 Tcheck.java'");
    assert_script_run("podman exec sut sh -c 'javac Tcheck.java'");
    assert_script_run("podman exec sut sh -c 'java Tcheck > result.txt'");
    my $EX_TCHECK = get_var("EX_TCHECK", "https://gitlab.suse.de/qe-security/testing/-/raw/main/data/openjdk/Tcheck.txt");
    assert_script_run("podman exec sut sh -c 'wget --quiet --no-check-certificate $EX_TCHECK'");
    my $out = script_output("podman exec sut sh -c 'diff -a Tcheck.txt result.txt'");
    record_info("FAIL", "Actually result VS Expected result: $out", result => 'fail') if ($out ne '');
}

sub test_flags {
    return {milestone => 0, fatal => 0, no_rollback => 1}
}

1;
