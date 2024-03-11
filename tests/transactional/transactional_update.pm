# SUSE's openQA tests
#
# Copyright 2020 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Package: transactional-update rebootmgr
# Summary: Test transactional updates
#   Installs & remove ptf, update, rollback
#   Check that system was rebooted and mounted snapshot changed
#   Check that expected package version match
# Maintainer: Martin Kravec <mkravec@suse.com>
# Tags: poo#14444

use strict;
use warnings;
use base "consoletest";
use testapi;
use version_utils qw(is_staging is_opensuse is_leap is_sle is_sle_micro is_leap_micro is_alp);
use transactional;
use utils;
use serial_terminal;


=head2 check_package

check_package([stage => $stage, package => $package]);

Check that package presence & version are as expected

Optional C<$stage> can be specified with possible values are 'no', 'in' and 'up'. default is 'no'.
Optional C<$package> can be specified name of rpm file. default is 'update-test-security'.

=cut
sub check_package {
    my (%args) = @_;
    my $stage = $args{stage} // 'no';
    my $package = $args{package} // 'update-test-security';
    my $in_vr = rpmver('vr');

    if ($stage eq 'no') {
        assert_script_run "! rpm -q $package";
    } elsif ($stage eq 'in') {
        assert_script_run "rpm -q --qf '%{V}-%{R}' $package | grep -x $in_vr";
    } elsif ($stage eq 'up') {
        my ($in_ver, $in_rel) = split '-', $in_vr;
        my ($up_ver, $up_rel) = split '-', script_output("rpm -q --qf '%{V}-%{R}' $package");

        $up_rel =~ s/lp\d+\.(?:mo\.)?//;
        $in_ver = version->declare($in_ver);
        $in_rel = version->declare($in_rel);
        $up_ver = version->declare($up_ver);
        $up_rel = version->declare($up_rel);

        return if $up_ver > $in_ver;
        return if $up_rel > $in_rel && $up_ver == $in_ver;
        die "Bad version: in:$in_ver-$in_rel up:$up_ver-$up_rel";
    } else {
        die "Unknown stage: $stage";
    }
}

sub run {
    select_serial_terminal;

    script_run "rebootmgrctl set-strategy off";

    #get_utt_packages;

    #record_info 'Install ptf', 'Install package - snapshot #1';
    #trup_call "ptf install" . rpmver('security');
    my $snap1 = script_output "snapper list | tail -1 | cut -d'|' -f1 | tr -d ' *'";
    #record_info("pkgs", script_output("zypper search -u"));
    record_info 'Snapshot', $snap1;
    trup_call "pkg in git";
    check_reboot_changes;
    #check_package(stage => 'in');
    assert_script_run('rpm -q git');

    # Find snapshot number for rollback
    my $snap2 = script_output "snapper list | tail -1 | cut -d'|' -f1 | tr -d ' *'";
    record_info 'Snapshot', $snap2;

    #record_info 'Remove pkg', 'Remove package - snapshot #4';
    #trup_call 'pkg remove update-test-security';
    #check_reboot_changes;
    #check_package;

    trup_call "rollback $snap1";
    check_reboot_changes;
    #check_package(stage => 'in');
    assert_script_run('rpm -q git');
}

sub test_flags {
    return {no_rollback => 1};
}

1;
