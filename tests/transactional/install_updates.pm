# SUSE's openQA tests
#
# Copyright 2021 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Summary: Install Update repos in transactional server
# Maintainer: qac team <qa-c@suse.de>

use base "consoletest";
use testapi;
use qam;
use transactional;
use version_utils 'is_sle_micro';
use serial_terminal;
use utils qw(script_retry fully_patch_system);

sub update_system {
    # By default we use 'up', but this covers also the case of 'patch'
    if (get_var('TRANSACTIONAL_UPDATE_PATCH')) {
        record_info('PATCH', 'Patching system');
        fully_patch_system(trup_call_timeout => 1800);
    } else {
        record_info('UPDATE', 'Updating system');
        trup_call('up', timeout => 1800);
        process_reboot(trigger => 1);
    }
}

sub run {
    my ($self) = @_;

    select_serial_terminal;

    if (is_sle_micro) {
        script_retry('curl -k https://ca.suse.de/certificates/ca/SUSE_Trust_Root.crt -o /etc/pki/trust/anchors/SUSE_Trust_Root.crt', timeout => 100, delay => 30, retry => 5);
        script_retry('pgrep update-ca-certificates', retry => 5, delay => 2, die => 0);
        assert_script_run 'update-ca-certificates -v';
    }

    record_info('Updates', script_output('zypper lu'));
    record_info('LOCKS');
    #assert_script_run 'zypper addlock shim dracut dracut-transactional-update';
    #assert_script_run 'zypper addlock shim dracut dracut-kiwi-lib dracut-kiwi-oem-dump dracut-kiwi-oem-repart dracut-transactional-update grub2 grub2-i386-pc grub2-snapper-plugin grub2-x86_64-efi cockpit-selinux container-selinux libselinux1 patterns-base-selinux python3-selinux selinux-policy selinux-policy-targeted selinux-tools swtpm-selinux kernel-default libbd_crypto2 python311-M2Crypto python311-cryptography coreutils-systemd util-linux-systemd libsystemd0 systemd systemd-container systemd-coredump util-linux-systemd pam pam-config pam_pwquality pam_u2f';
    assert_script_run 'zypper addlock dracut pam pam-config';
    update_system;

    # Clean the journal to avoid capturing bugs that are fixed after installing updates
    my $journal_before = "/tmp/journal_before.txt";
    assert_script_run("journalctl --no-pager -o short-precise | tail -n +2 > $journal_before", fail_message => "journal log export failed");
    upload_logs($journal_before);
    assert_script_run('journalctl --sync --flush --rotate --vacuum-time=1second', fail_message => "clearing the journal failed");
    script_run("rm -f $journal_before");

    # Now we add the test repositories and do a system update
    #add_test_repositories;
    update_system unless get_var('DISABLE_UPDATE_WITH_PATCH');

    # after update, clean the audit log to make sure there aren't any leftovers that were already fixed
    # see poo#169090
    if (is_sle_micro) {
        # upon reboot, auditd service will be restarted and logfile recreated
        assert_script_run 'tar --warning=no-file-changed -zcf /tmp/audit_before.tgz /var/log/audit';
        upload_logs '/tmp/audit_before.tgz';
        assert_script_run 'rm -f /var/log/audit/* /tmp/audit_before.tgz';
    }
    process_reboot(trigger => 1);
}

sub test_flags {
    return {fatal => 1, milestone => 1};
}

1;
