# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

# Author:  Steve Freegard <steve.freegard@fsl.com>

=head1 NAME

SaveHits - save a copy of messages that hit specific rules.

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::SaveHits

  savehits_dir	/var/spool/savehits

  savehits_rule	BAYES_99 BAYES_95
  savehits_rule	MISSING_MID

=head1 DESCRIPTION

This plugin saves a copy of messages that hit one or more of the specified 
rules.

As a single message could hit multiple rules, this plugin stores the actual 
message into <savehits_dir>/msgs/<YYYYMMDD>/<sha1> where <sha1> is the SHA1 digest 
of the full message including headers.  This also serves to prevent the storage 
of duplicate messages.

Once the message file is stored, each rule that matches the B<savehits_rule> list 
is stored as <savehits_dir>/rules/<RULE_NAME>/<YYYYMMDD>/<symlink> where <symlimk> 
is a symlink to the stored message file.

=cut

package Mail::SpamAssassin::Plugin::SaveHits;
my $VERSION = 0.1;

use strict;
use Mail::SpamAssassin::Plugin;
use Digest::SHA1 qw{sha1_hex};
use File::Path;
use File::Basename;
use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg {
  Mail::SpamAssassin::Plugin::dbg ("SaveHits: @_");
}

sub new {
  my ($class, $mailsa) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);
  return $self;
}

sub parse_config {
 my ($self,$params) = @_;
 return 0 unless ($params->{key} =~ /^savehits_(\S+)$/i);
 my $key = $1;
 if($key =~ /^rule$/i) {
  my(@split) = split(/\s+/,$params->{value});
  foreach my $rule (@split) {
   $self->{main}->{conf}->{'savehits_rules'}->{$rule} = 1 if $rule;
   dbg("Added rule $rule to save list");
  }
 }
 if($key =~ /^dir$/i) {
  $self->{main}->{conf}->{$params->{key}} = $params->{value};
 }
 $self->inhibit_further_callbacks();
 return 1;
}


sub check_end {
 my ($self, $params) = @_; 
 my ($pms) = $params->{permsgstatus};
 my ($saverules) = $self->{main}->{conf}->{'savehits_rules'};
 my ($savedir) = $self->{main}->{conf}->{'savehits_dir'};
 return 0 if not $savedir;
 my ($msg) = $pms->get_message();
 my ($pristine) = $msg->get_pristine();
 my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime;
 my ($date) = sprintf("%d%02d%02d",$year+1900,$mon+1,$mday);
 my(@hits) = split(',',($pms->get_names_of_tests_hit.','.$pms->get_names_of_subtests_hit));
 my(%rules);
 map { $rules{$_}++ } @hits;
 foreach my $rule (keys %rules) {
  if(defined($saverules->{$rule})) {
   dbg("Got hit: $rule");
   my $hash = sha1_hex($pristine);
   my $filename = "$savedir/msgs/$date/$hash";
   my $linkname = "$savedir/rules/$rule/$date/$hash";
   # Untaint
   $filename =~ /^([\/-\@\w.]+)$/;
   $filename = $1;
   $linkname =~ /^([\/-\@\w.]+)$/;
   $linkname = $1;
   eval { mkpath(dirname($filename)); };
   if ($@) {
    dbg("error: $@");
    return 0;
   }
   eval { mkpath(dirname($linkname)); };
   if ($@) {
    dbg("error: $@");
    return 0;
   }
   if (! -f $filename) {
    dbg("Saving message to $filename");
    eval { open(FILE, ">$filename"); };
    if ($@) {
     dbg("error: $@");
     return 0;
    }
    print FILE $pristine;
    close(FILE);
   }
   if ((! -f $linkname) && (-f $filename)) {
    dbg("Creating symlink $linkname to $filename");
    eval { symlink($filename, $linkname); };
    if ($@) {
     dbg("error: $@");
     return 0;
    }
   }
  }
 }
 return 1;
}

1;
