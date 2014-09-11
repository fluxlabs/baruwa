#
# Mail::SpamAssassin::Plugin::SAGrey
# version 0.02, June 10, 2006
#
# Eric A. Hall, <ehall@ntrg.com>
# http://www.ntrg.com/misc/sagrey/
#
# <@LICENSE>
# Copyright 2005 Eric A. Hall <ehall@ntrg.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>
#
# CHANGELOG:
#
# v0.02 -- fixed bug with sagrey_header_field parsing
#
# v0.01 -- initial release
#

#
# SAGrey is a lightweight SpamAssassin plugin that is intended to
# assist with certain greylisting mechanisms. SAGrey first looks to 
# see if the current score of the current message exceeds the user-
# defined threshold value (as set in one of the cf files), and then
# looks to see if the message sender's email and IP address tuple are
# already known to the auto-whitelist factory. If the message is spam
# and the sender is unknown, the SAGREY rule fires and adds 1.0 (by
# default) to the current message score. This can be used to perform
# additional greylisting functions (EG, having your delivery or
# transfer agent check for the presence of the SAGREY rule or the
# "X-Spam-*-SAGrey" header field), or can be used to simply penalize
# likely spam from throwaway or zombie accounts.
#

#
# declare the package and necessary modules
#
package Mail::SpamAssassin::Plugin::SAGrey;

our $VERSION = "0.02";

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::AutoWhitelist;

use strict;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

#
# register the module
#
sub new {

	#
	# object constructor crap
	#
	my $class = shift;
	my $mailsaobject = shift;

	$class = ref($class) || $class;
	my $self = $class->SUPER::new($mailsaobject);
	bless ($self, $class);

	#
	# disable the header_field reporting by default
	#
	$self->{header_field} = "off";

	#
	# declare the eval statements
	#
	$self->register_eval_rule("sagrey");

	return $self;
}

#
# this gets called as each parameter in the .cf file is encountered.
# note that parameter names are lowercased by the calling function.
#
sub parse_config {

#
# suck down the config object
#
my ($self, $config) = @_;

	#
	# read and verify sagrey_header_field
	#
	if ($config->{key} eq 'sagrey_header_field') {

		if ($config->{value} =~ /^[\'\"]?\s*(on|off)\s*[\'\"]?$/i) {

			dbg ("Filtered\: $config->{key}\: ".
				"using \"$1\"");

			$self->{header_field} = $1;
		}

		else {
			dbg ("Filtered\: $config->{key}\: ".
				"\"$config->{value}\" is not a valid ".
				"toggle value; using default value of ".
				"\"$self->{header_field}\"");
		}

		$self->inhibit_further_callbacks();

		return 1;
	}

	#
	# all other config statements are unknown
	#
	return 0;
}

#
# this is the main loop
#
sub sagrey {

	#
	# suck down the permsgstatus object
	#
	my ($self, $permsgstatus) = @_;

	#
	# load up the current values
	#
	if ($permsgstatus->get_hits() > $permsgstatus->get_required_hits()) {

		dbg ("Filtered\: message score indicates spam ... looking for sender history");

		#
		# see if the AWL rule fired (if so, then sender tuple is known)
		#
		if ($permsgstatus->get_names_of_tests_hit() =~ /\bAWL\b/) {

			dbg ("Filtered\: sender email and host addresses seen before ... ignoring");

			if ($self->{header_field} =~ /on/i) {

				$permsgstatus->{main}->{conf}->{headers_spam}->{"SAGrey"} =
					"known sender tuple";
			}

			return 0;
		}

		else {
			dbg ("Filtered\: unknown sender ... " .
				"probably a throw-away or zombie account");

			if ($self->{header_field} =~ /on/i) {

				$permsgstatus->{main}->{conf}->{headers_spam}->{"SAGrey"} =
					"unknown sender tuple";
			}

			return 1;
		}
	}

	else {
		dbg ("Filtered\: message score does not indicate spam ... ignoring");

		return 0;
	}

	#
	# shouldn't be here -- return zero just in case
	#
	return 0;
}

#
# print debug messages
# 
sub dbg {

	Mail::SpamAssassin::dbg (@_);
}

1;

