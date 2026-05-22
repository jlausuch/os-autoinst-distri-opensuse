# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP

# Package: NA
# Summary: Extract information from the SUT
# Maintainer: jalausuch@suse.com

use Mojo::Base 'consoletest';
use testapi;
use serial_terminal 'select_serial_terminal';
use utils;

sub run {
    select_serial_terminal;
    record_info('os-release', script_output('cat /etc/os-release'));
    record_info('Repos', script_output('zypper lr -u'));
    record_info('Kernel', script_output('uname -a'));
    record_info('Kernel-RPM', script_output('rpm -qi kernel-default'));
    record_info('RPM', script_output('rpm -qa'));
    record_info('lsmod', script_output('lsmod'));
    record_info('dmesg', script_output('dmesg'));
    record_info('Zypper', script_output('zypper search'));
}

1;
