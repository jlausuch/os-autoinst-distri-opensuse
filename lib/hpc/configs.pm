# SUSE's openQA tests
#
# Copyright 2019-2020 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Summary: Base module for HPC config handling
# Maintainer: Kernel QE <kernel-qa@suse.de>

package hpc::configs;
use Mojo::Base 'hpcbase', -signatures;
use testapi;
use utils;
use Storable;
use Tie::IxHash;
use version_utils 'is_sle';

our @EXPORT = qw(
  prepare_slurm_conf
  prepare_slurmdb_conf
);

my (%slurm_config);
tie %slurm_config, 'Tie::IxHash';

my (%slurm_config_NODES);
tie %slurm_config_NODES, 'Tie::IxHash';

my (%slurm_config_PARTITION);
tie %slurm_config_PARTITION, 'Tie::IxHash';

my (%slurm_config_PARTITION_MINOR);
tie %slurm_config_PARTITION_MINOR, 'Tie::IxHash';

=head2

Default slurm.conf always set to the latest supported version

=cut
%slurm_config = (
    ClusterName => 'linux',
    SlurmctldHost => 'masterctl',
    "\#SlurmctldHost" => '',
    SlurmUser => 'slurm',
    "\#SlurmdUser" => '',
    SlurmctldPort => '6817',
    SlurmdPort => '6818',
    AuthType => 'auth/munge',
    "\#JobCredentialPrivateKey" => '',
    "\#JobCredentialPublicCertificate" => '',
    StateSaveLocation => '/var/lib/slurm',
    SlurmdSpoolDir => '/var/spool/slurm',
    SwitchType => 'switch/none',
    MpiDefault => 'none',
    SlurmctldPidFile => '/var/run/slurm/slurmctld.pid',
    SlurmdPidFile => '/var/run/slurm/slurmd.pid',
    ProctrackType => 'proctrack/pgid',
    "\#PluginDir" => '',
    "\#FirstJobId" => '',
    "\#MaxJobCount" => '',
    "\#PlugStackConfig" => '',
    "\#PropagatePrioProcess" => '',
    "\#PropagateResourceLimits" => '',
    "\#PropagateResourceLimitsExcept" => '',
    "\#Prolog" => '',
    "\#Epilog" => '',
    "\#SrunProlog" => '',
    "\#SrunEpilog" => '',
    "\#TaskProlog" => '',
    "\#TaskEpilog" => '',
    "\#TaskPlugin" => '',
    "\#TrackWCKey" => '',
    "\#TreeWidth" => '',
    "\#TmpFS" => '',
    "\#UsePAM" => '',
    SlurmctldTimeout => '300',
    SlurmdTimeout => '300',
    InactiveLimit => '0',
    MinJobAge => '300',
    KillWait => '30',
    Waittime => '0',
    SchedulerType => 'sched/backfill',
    "\#SchedulerAuth" => '',
    "\#SelectType" => '',
    "\#PriorityType" => '',
    "\#PriorityDecayHalfLife" => '',
    "\#PriorityUsageResetPeriod" => '',
    "\#PriorityWeightFairshare" => '',
    "\#PriorityWeightAge" => '',
    "\#PriorityWeightPartition" => '',
    "\#PriorityWeightJobSize" => '',
    "\#PriorityMaxAge" => '',
    SlurmctldDebug => 'debug5',
    SlurmctldLogFile => '/var/log/slurmctld.log',
    SlurmdDebug => '3',
    SlurmdLogFile => '/var/log/slurmd.log',
    JobCompType => 'jobcomp/none',
    "\#JobCompLoc" => '',
    "\#JobAcctGatherType" => '',
    "\#JobAcctGatherFrequency" => '',
    "\#AccountingStorageType" => '',
    "\#AccountingStorageHost" => '',
    "\#AccountingStorageLoc" => '',
    "\#AccountingStoragePass" => '',
    "\#AccountingStorageUser" => '',
    PropagateResourceLimitsExcept => 'MEMLOCK',
    NODES => undef,
    PARTITION => undef,
    PARTITION_MINOR => undef
);

%slurm_config_NODES = (
    NodeName => '',
    Sockets => '1',
    CoresPerSocket => '1',
    ThreadsPerCore => '1',
    State => 'unknown'
);

%slurm_config_PARTITION = (
    PartitionName => 'normal',
    Nodes => '',
    Default => 'YES',
    MaxTime => '24:00:00',
    State => 'UP',
);

%slurm_config_PARTITION_MINOR = (
    PartitionName => 'minor',
    Nodes => '',
    Default => 'NO',
    MaxTime => '24:00:00',
    State => 'UP',
);

$slurm_config{NODES} = \%slurm_config_NODES;
$slurm_config{PARTITION} = \%slurm_config_PARTITION;
$slurm_config{PARTITION_MINOR} = \%slurm_config_PARTITION_MINOR;

my %slurmdb_config;
tie %slurmdb_config, 'Tie::IxHash';

=head2

Default slurmdb.conf always set to the latest supported version
#TODO

=cut

=head2

Prepare slurm.conf based on test requirements and settings. This
should usually be called from the master node and then get distributed
among the nodes of the cluster.

=cut

sub prepare_slurm_conf ($self) {
    my $slurm_conf = get_required_var('SLURM_CONF');

    my @cluster_ctl_nodes = $self->master_node_names();
    my @cluster_compute_nodes = $self->slave_node_names();
    my $cluster_ctl_nodes = join(',', @cluster_ctl_nodes);
    my $cluster_compute_nodes = join(',', @cluster_compute_nodes);

    $slurm_config{NODES}{NodeName} = "$cluster_ctl_nodes,$cluster_compute_nodes";
    $slurm_config{PARTITION}{Nodes} = "$cluster_ctl_nodes,$cluster_compute_nodes";
    $slurm_config{PARTITION_MINOR}{Nodes} = "$cluster_ctl_nodes,$cluster_compute_nodes";
    $slurm_config{SlurmctldHost} = get_var('HOSTNAME');
    $slurm_config{SlurmctldDebug} = 'debug5';

    if (($slurm_conf eq 'accounting') or ($slurm_conf eq 'nfs_db')) {
        $slurm_config{JobAcctGatherType} = 'jobacct_gather/linux';
        $slurm_config{JobAcctGatherFrequency} = '12';
        $slurm_config{AccountingStorageType} = 'accounting_storage/slurmdbd';
        $slurm_config{AccountingStorageHost} = "$cluster_compute_nodes[-1]";
        $slurm_config{AccountingStoragePort} = '20088';
    }
    if (($slurm_conf eq 'ha') or ($slurm_conf eq 'nfs_db')) {
        $slurm_config{SlurmctldHost_tmp} = "$cluster_ctl_nodes[1]";
        $slurm_config{StateSaveLocation} = '/shared/slurm/';
        $slurm_config{SlurmctldTimeout} = '15';
        $slurm_config{SlurmdTimeout} = '60';
    }

    script_run("echo '#slurm.conf generated by the tests' > /etc/slurm/slurm.conf");
    my $backup = 0;
    my @pairs = ();
    my $NODES = '';
    my $PARTITION = '';
    my $PARTITION_MINOR = '';
    while (my ($key, $value) = each %slurm_config) {
        push(@pairs, $key . '=' . $value) unless ($key eq 'NODES') or ($key eq 'PARTITION') or ($key eq 'PARTITION_MINOR')
          or ($key eq 'SlurmctldHost') or ($key eq 'SlurmctldHost_tmp');
        if (($key eq 'SlurmctldHost') or ($key eq 'SlurmctldHost_tmp')) {
            my $tmp_key = '';
            if (is_sle('<15-sp1')) {
                if ($backup == 0) {
                    $tmp_key = 'ControlMachine';
                    $backup = 1;
                }
                else {
                    $tmp_key = 'BackupController';
                }
            }
            else {
                $tmp_key = 'SlurmctldHost';
            }
            push(@pairs, $tmp_key . '=' . $value);
        }
        if ($key eq 'NODES') {
            my @pairs = ();
            while (my ($key, $value) = each %{$slurm_config{NODES}}) {
                push(@pairs, $key . '=' . $value);
            }
            $NODES = join(' ', @pairs);
        }
        if ($key eq 'PARTITION') {
            my @pairs = ();
            while (my ($key, $value) = each %{$slurm_config{PARTITION}}) {
                push(@pairs, $key . '=' . $value);
            }
            $PARTITION = join(' ', @pairs);
        }
        if ($key eq 'PARTITION_MINOR') {
            my @pairs = ();
            while (my ($key, $value) = each %{$slurm_config{PARTITION_MINOR}}) {
                push(@pairs, $key . '=' . $value);
            }
            $PARTITION_MINOR = join(' ', @pairs);
        }
    }
    my $slurm_config_tmp = join('+', @pairs);
    script_run("echo $slurm_config_tmp | tee -a /etc/slurm/slurm.conf");
    script_run("echo $NODES | tee -a /etc/slurm/slurm.conf");
    script_run("echo $PARTITION | tee -a /etc/slurm/slurm.conf");
    script_run("echo $PARTITION_MINOR | tee -a /etc/slurm/slurm.conf");
    script_run("tr '+' '\\n' < /etc/slurm/slurm.conf > /etc/slurm/slurm.conf_tmp");
    script_run("mv /etc/slurm/slurm.conf_tmp /etc/slurm/slurm.conf");
}

=head2

Prepare slurmdbd.conf based on test requirements and settings

=cut

sub prepare_slurmdb_conf ($self) {
    my @cluster_compute_nodes = $self->slave_node_names();

    my $config = <<"EOF";
sed -i "/^DbdAddr.*/c\\#DbdAddr" /etc/slurm/slurmdbd.conf
sed -i "/^DbdHost.*/c\\DbdHost=$cluster_compute_nodes[-1]" /etc/slurm/slurmdbd.conf
sed -i "/^#StorageHost.*/c\\StorageHost=$cluster_compute_nodes[-1]" /etc/slurm/slurmdbd.conf
sed -i "/^#StorageLoc.*/c\\StorageLoc=slurm_acct_db" /etc/slurm/slurmdbd.conf
sed -i "/^#DbdPort.*/c\\DbdPort=20088" /etc/slurm/slurmdbd.conf
sed -i "/^DebugLevel.*/c\\DebugLevel=debug5" /etc/slurm/slurmdbd.conf
EOF
    assert_script_run($_) foreach (split /\n/, $config);
}

1;
