# SUSE's openQA tests
#
# Copyright 2024 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Summary: Run the SCLS test suite provided by SAP
# Requires: ENV variable SLCS pointing to installation media
# Maintainer: QE-SAP <qe-sap@suse.de>

use Mojo::Base qw(sles4sap);
use serial_terminal 'select_serial_terminal';
use testapi;

sub run {
    my ($self) = @_;

    select_serial_terminal;

    my $scls_version = get_required_var('SLCS_VERSION');
    my $nfs_path = get_required_var('SLCS_PATH') . $scls_version;
    my ($proto, $path) = $self->fix_path($nfs_path);

    #record_info("sapconf", script_output('zypper se sapconf'));
    #record_info("insserv-compat", script_output('zypper se insserv-compat'));
    #record_info("numactl", script_output('zypper se numactl'));
    #record_info("libatomic1", script_output('zypper se libatomic1'));

    # Mount media
    $self->mount_media($proto, $path, '/slcs');
    #record_info("mnt", script_output('find /mnt'));
    #record_info("slcs", script_output('find /slcs'));
    #assert_script_run("cd /slcs");
    #my $tarball = script_output("ls slcs*.tar.gz");
    #record_info("tarball", $tarball);
    #assert_script_run("time tar -xzvf $tarball", timeout => 600);
    record_info("slcs", script_output('find /slcs'));
    #assert_script_run("cd /slcs && chmod +x *.sh && ls -lh");
    assert_script_run("cd /slcs");
    assert_script_run('find . -name "*.sh" -exec chmod +x {} \;');
    assert_script_run('chmod +x /slcs/sapcds/Linuxx86_64/SWPM/sapinst');
    record_info("slcs", script_output('find /slcs'));

    my $instance_type = get_required_var('INSTANCE_TYPE');
    my $instance_id = get_required_var('INSTANCE_ID');
    my $sid = get_required_var('INSTANCE_SID');
    my $hostname = get_var('INSTANCE_ALIAS', '$(hostname)');
    my $params_file = "/sapinst/$instance_type.params";
    # set timeout as 1800 as workaround for slow nfs
    my $timeout = bmwqemu::scale_timeout(1800);    # Time out for NetWeaver's sources related commands
    my $product_id = 'NW_ABAP_ASCS';
    my @sapoptions = qw(SAPINST_START_GUISERVER=false SAPINST_SKIP_DIALOGS=true SAPINST_SLP_MODE=false IS_HOST_LOCAL_USING_STRING_COMPARE=true);
    push @sapoptions, "SAPINST_USE_HOSTNAME=$hostname";
    push @sapoptions, "SAPINST_INPUT_PARAMETERS_URL=$params_file";
    push @sapoptions, "SAPINST_EXECUTE_PRODUCT_ID=$product_id:NW750.HDB.ABAPHA";
    $self->add_hostname_to_hosts;
    # Use the correct Hostname and InstanceNumber in SAP's params file
    # Note: $hostname can be '$(hostname)', so we need to protect with '"'
    assert_script_run "sed -i -e \"s/%HOSTNAME%/$hostname/g\" -e 's/%INSTANCE_ID%/$instance_id/g' -e 's/%INSTANCE_SID%/$sid/g' $params_file";


    assert_script_run("bash -x ./install.sh", timeout => 600);

}

1;
