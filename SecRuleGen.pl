#!/usr/bin/perl
# Build mod security rules from swagger's specifications to protect a web service behind an hardened proxy
# for a better understanding of mod security see https://www.feistyduck.com/books/modsecurity-handbook and 
# http://eu.wiley.com/WileyCDA/WileyTitle/productCd-1118362187.html
use strict;
use warnings;
use English;
use LWP::UserAgent;
use JSON;
no warnings "experimental::autoderef";

sub onError() {
        print "E : " . shift . "\n";
        print "Usage : ./SecGenRule.pl \"url to swagger specifications\" [whitelist] [rate limit]\n\n";
	print "\t - whitelist : list of ip adresses/subnets to exclude from rate limit rules\n";
	print "\t - rate limit : maximum number of request per user per endpoint per minute\n";
        exit 1;
}

if ( @ARGV < 1 ) {
        &onError("url not supplied");
}

my $url = $ARGV[0];
my $specs = '';
# maximum number of call to an endpoint per minute 
my $maximumRateLimit = 50;
# list of IP adresses/subnets to exclude from rate limit rules
my $whitelistRateLimit = "127.0.0.1";
# Modsec id rule, start at 200, valid in most standard configuration
my $secRuleID = 200;

if ( exists($ARGV[1]) ) {
	if ( $ARGV[1] =~ m/[0-9\.,\/]/ ) {
		$whitelistRateLimit = $ARGV[1];
	}
	else {
		&onError("whitelist invalid");
	}
}

if ( exists($ARGV[2]) ) {
        if ( $ARGV[2] =~ m/[0-9]/ ) {
                $maximumRateLimit = $ARGV[2];
        }
	else {
                &onError("rate limit invalid");
        }
}

# Downlad the json given as argument
sub DownlSpecs() {
        my ($dest_file) = @_;
        if ( $dest_file =~ m/^http/ ) {
                $dest_file =~ s/^.*\/\///;
        }
	$dest_file =~ s/\/.*$//;
        $dest_file .= ".json";
        my $ua = LWP::UserAgent->new();
        my $req = HTTP::Request->new(GET => $url);
        my $res = $ua->request($req);
        if ( $res->is_success ) {
                if ( -e $dest_file ) {
                        unlink $dest_file;
                }
                open (TARGET, '>', $dest_file) or die $!;
                print TARGET $res->content;
                close(TARGET);
        }
        else {
                &onError("invalid url");
        }
	return $dest_file;
}

# Generate the ID for every modsec rule
sub SecRuleIDGen() {
	$secRuleID++;
	return $secRuleID;
}

# Dig into swagger argument definition to extract every possible argument
sub ManageComplexArg {
	my ($root, $ref) = @_;
	my $parameters = '';
	$ref  =~ s/^.*\///g;
	my @properties = keys $specs->{"definitions"}{$ref}{"properties"};
	foreach my $property (sort @properties) {
		my $validValues = '';
		my $newParam = '';
		my $parsedArgs = '';
		my $isDefined = 0;
		if ( exists($specs->{"definitions"}{$ref}{"properties"}{$property}{"items"}{"\$ref"}) ) {
			$isDefined = 1;
			$parameters .= &ManageComplexArg($property, $specs->{"definitions"}{$ref}{"properties"}{$property}{"items"}{"\$ref"});
		}
		if ( exists($specs->{"definitions"}{$ref}{"properties"}{$property}{"\$ref"}) ) {
                        $isDefined = 1;
                        $parameters .= &ManageComplexArg($property, $specs->{"definitions"}{$ref}{"properties"}{$property}{"\$ref"});
                }
		if ( !$isDefined ) {
			if ( $root =~ m/NULL/ ) {
				$newParam = $property;
			}
			else {
				$newParam = $root . "\\." . $property;
			}
			if ( exists($specs->{"definitions"}{$ref}{"properties"}{$property}{"enum"}) && index($parsedArgs, $property . ",") == -1 && index($parsedArgs, "," . $property) == -1 ) {
				$parsedArgs .= $property . ",";
				my @values = keys $specs->{"definitions"}{$ref}{"properties"}{$property}{"enum"};
                	        foreach my $value (@values) {
                        			$validValues .= $specs->{"definitions"}{$ref}{"properties"}{$property}{"enum"}[$value] . "|";
                			}
					print "\t\t" . &BuildModsecArgRule($newParam, $validValues) . "\n";
			}
			if ( $parameters !~ "|" . $newParam . "|" ) {
				$parameters .= $newParam . "|";
			}
		}
	}
	return $parameters;
}

# Remove var from url (such as {id} or {email}), replace it with a regex matching anything exept "/"
sub CleanArgFromUrl {
	my ($url) = @_;
	$url =~ s/\{[a-zA-Z0-9\-_\.]*\}/\(\?\!\(\.\*\/\)\)/;
	if ( $url =~ m/\{.*\}/) {
		&CleanArgFromUrl($url);
	}
	else {
		return($url);
	}
}

# Generate a valid LocationMatch directive for apache from the given URL
sub BuildModsecLocationMatch {
	my ($url) = @_;
	if ( $url =~ m/\{.*\}/ ) {
		$url = &CleanArgFromUrl($url);
	}
	$url = "<LocationMatch \"^" . $url . "\$\">";
	return($url);
}

# Generate a modsec's arg_names rule from given list of argument, basicaly we are checking if the  supplied argument is listed in the spec
sub BuildModsecArgNamesRule {
	my ($arg) = @_;
	$arg =~ s/\|$//;
	my $rule = "SecRule ARGS_NAMES \"!^(?:" . $arg . ")\$\" \"phase:2,t:none,deny,id:'" . &SecRuleIDGen . "',msg:'Unrecognized argument',logdata:%{TX.0}\"";
	return $rule;
}

# Generate a modsec's request_method rule from given list of methods extracted from swagger's specifications
sub BuildModsecReqMethodRule {
	my @methods = @_;
	my $rule = "SecRule REQUEST_METHOD \"!^(?:";
	foreach my $method (@methods) {
		$rule .= uc($method) . "|";
	}
	$rule =~ s/\|$/\|OPTIONS/;
	$rule .= ")\$\" \"phase:2,t:none,deny,id:'" . &SecRuleIDGen . "',msg:'Unauthorized method',logdata:%{REQUEST_METHOD}\"";
	return $rule;
}

# Build a modsec request header rule to check if the request content-type match the on specified in swagger's endpoint description
sub BuildModsecContentTypeRule {
	my ($contentType) = @_;
	$contentType =~ s/\|$//;
	my $rule = "SecRule REQUEST_HEADERS:Content-Type \"!\@rx (?i)^(";
	$rule .= $contentType;
	$rule .= ")\" \"phase:1,t:none,deny,id:'" . &SecRuleIDGen . "',msg:'Invalid content-type',logdata:%{MATCHED_VAR}\"";
	return $rule;
}

# Build a rule to check if the var content is supported
sub BuildModsecArgRule {
	my ($argName, $values) = @_;
	$values =~ s/\|$//;
	$argName =~ s/\\//;
	my $rule = "SecRule ARGS:" . $argName . " \"!^(?:" . $values . ")\$\" \"phase:2,t:none,deny,id:'" . &SecRuleIDGen . "',msg:'Bad content',logdata:%{MATCHED_VAR}\"";
	return $rule;
}

# Build a rule to check if a post parameter's content is valid against swagger's supplied format
sub BuildModsecDataTypeRule() {
	my ($argName, $dataType, $dataFormat) = @_;
	my $matchedFormat = 0;
	my $rule = "SecRule ARGS:" . $argName . " \"!^(?:";
	if ( $dataType =~ m/integer/) {
		$rule .= "[0-9\-]*";
		$matchedFormat = 1;
	}
	if ( $dataType =~ m/number/) {
		$rule .= "[0-9\.,\-]*";
		$matchedFormat = 1;
        }
        if ( $dataType =~ m/boolean/) {
		$rule .= "0|1|true|false|TRUE|FALSE";
		$matchedFormat = 1;
        }
	if ( $matchedFormat ) {
		$rule .= ")\$\" \"phase:2,t:none,deny,id:'" . &SecRuleIDGen . "',msg:'Bad content format',logdata:%{MATCHED_VAR}\"";;
		return $rule;
	}
	else {
		&onError("data format unknown for arg $argName");
	}
}

# Build a batch of rule to control the max number request per user per minute
sub BuildModSecRateLimitRule() {
	my ($endpoint) = @_;
	$endpoint =~ s/\{.*\}//;
	my $rule = "SecRule REMOTE_ADDR \"\@ipMatch " . $whitelistRateLimit . "\" \"phase:1,skip:4,nolog,id:'" . &SecRuleIDGen . "'\"\n\t\t";
	$rule .= "SecAction \"initcol:ip=\%{REMOTE_ADDR}_\%{TX.uahash},pass,nolog,id:'" . &SecRuleIDGen . "'\"\n\t\t";
	$rule .= "SecAction \"phase:5,deprecatevar:ip." . $endpoint . "=" . $maximumRateLimit . "/60,pass,nolog,id:'" . &SecRuleIDGen . "'\"\n\t\t";
	$rule .= "SecRule IP:" . $endpoint . " \"\@gt " . $maximumRateLimit . "\" \"phase:2,pause:300,deny,setenv:RATELIMITED,skip:1,id:'" . &SecRuleIDGen . "',msg:'too many request per minute',logdata:%{MATCHED_VAR}\"\n\t\t";
	$rule .= "SecAction \"phase:2,pass,setvar:ip." . $endpoint . "=+1,nolog,id:'" . &SecRuleIDGen . "'\"";
	return $rule;
}

# Main routine, extract infos from the downloaded json and call subroutine to build modsec rules
sub ParseJson {
	my ($file) = @_;
        open ('JSON', '<', $file) or &onError("can't open file");
	my $content;
	while ( <JSON> ){
		$content .= $_;
	}
        $specs = decode_json($content);
        my @paths = keys $specs->{"paths"};
        foreach my $url (@paths) {
                my @methods = keys $specs->{"paths"}{$url};
		if ( defined($methods[0]) ) {
			print "\t" . &BuildModsecLocationMatch($url) . "\n";
			print "\t\t" . &BuildModsecReqMethodRule(@methods) . "\n";
			print "\t\t" . &BuildModSecRateLimitRule($url) . "\n";
			my $paramList = '';
			my $contentTypeList = '';
			my $parsedArgs = '';
			foreach my $method (@methods) {
				if ( exists($specs->{"paths"}{$url}{$method}{"parameters"}) ) {
					my @parameters = keys $specs->{"paths"}{$url}{$method}{"parameters"};
					foreach my $parameter (@parameters) {
						my $validValues = '';
						# If the argument has a definition
						if ( exists($specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"schema"}{"\$ref"}) ) {
							# And we haven't parsed it before
							if ( index($paramList, &ManageComplexArg("NULL", $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"schema"}{"\$ref"})) == -1 ) {
								$paramList .= &ManageComplexArg("NULL", $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"schema"}{"\$ref"});
							}
						}
						else {
							if ( index($paramList, $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"} . "|") == -1 && index($paramList, "|" . $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"}) == -1 ) {
								$paramList .= $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"} . "|";
							}
						}
						# If variable content are enumerated we build the matching rule
						if ( exists($specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"enum"}) && index($parsedArgs, $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"} . "," ) == -1 && index($parsedArgs, "," . $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"}) == -1 ) {
							$parsedArgs .= $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"} . ",";
							my @values = keys $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"enum"};
							foreach my $value (@values) {
								$validValues .= $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"enum"}[$value] . "|";
							}
							print "\t\t" . &BuildModsecArgRule($specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"}, $validValues) . "\n";
						}
						# If variable data type is supplied we build the matching rule
						if ( exists($specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"type"}) ) {
							# Skipping if data type is "string" or if data format is not supplied
							if ( ($specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"type"} !~ m/string/) && (exists($specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"format"})) ) {
								print "\t\t" . &BuildModsecDataTypeRule($specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"}, $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"type"}, $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"format"}) . "\n";
							}
						}
					}
				}
				# If a content type for input is specified we build the matching rule
				if ( exists($specs->{"paths"}{$url}{$method}{"consumes"}) ) {
					my @contentTypes =  keys $specs->{"paths"}{$url}{$method}{"consumes"};
					foreach my $contentType (@contentTypes){
						$contentTypeList .= $specs->{"paths"}{$url}{$method}{"consumes"}[$contentType] . "|";
					}
				}
			}
			if ( length($paramList) > 0 ) {
				print "\t\t" . &BuildModsecArgNamesRule($paramList) . "\n";
			}
			if ( length($contentTypeList) > 0 ) {
				print "\t\t" . &BuildModsecContentTypeRule($contentTypeList) . "\n";
			}
			print "\t</LocationMatch>\n";
		}
	}
}

my $file = &DownlSpecs($url);
&ParseJson($file);
unlink($file);
