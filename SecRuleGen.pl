#!/usr/bin/perl
#Build mod security rules from swagger's specifications to protect a web service behind an hardened proxy
#for a better understanding of mod security see https://www.feistyduck.com/books/modsecurity-handbook and 
#http://eu.wiley.com/WileyCDA/WileyTitle/productCd-1118362187.html
use strict;
use warnings;
use English;
use LWP::UserAgent;
use JSON;
no warnings "experimental::autoderef";

sub onError() {
        print "E : " . shift . "\n";
        print "Usage : ./SecGenRule.pl \"url to swagger specifications\"\n";
        exit 1;
}

if ( @ARGV < 1 ) {
        &onError("url not supplied");
}

my $url = $ARGV[0];
my $specs = '';
#modsec id rule, start at 200, valid in most standard configuration
my $secRuleID = 200;

#Downlad the json given as argument
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

#Generate the ID for every modsec rule
sub SecRuleIDGen() {
	$secRuleID++;
	return $secRuleID;
}

#idg into swagger argument definition to extract every possible argument
sub ManageComplexArg {
	my ($root, $ref) = @_;
	my $parameters = '';
	$ref  =~ s/^.*\///g;
	my @properties = keys $specs->{"definitions"}{$ref}{"properties"};
	foreach my $property (@properties) {
		my $isDefined = 0;
#		print "D : la definition " . $ref . " contient l'argument " . $property . "\n";
#		print "D : on verifie la presence de definitions/" . $ref . "/properties/" . $property . "/items/\$ref/\n";
		if (exists($specs->{"definitions"}{$ref}{"properties"}{$property}{"items"}{"\$ref"}) ) {
			$isDefined = 1;
#			print "D : l'argument " . $property . " est defini dans " . $specs->{"definitions"}{$ref}{"properties"}{$property}{"items"}{"\$ref"} . "\n";
			$parameters .= ManageComplexArg($property, $specs->{"definitions"}{$ref}{"properties"}{$property}{"items"}{"\$ref"});
		}
#		print "D : on verifie la presence de definitions/" . $ref . "/properties/" . $property . "/\$ref/\n";
		if (exists($specs->{"definitions"}{$ref}{"properties"}{$property}{"\$ref"}) ) {
                        $isDefined = 1;
#                        print "D : l'argument " . $property . " est defini dans " . $specs->{"definitions"}{$ref}{"properties"}{$property}{"\$ref"} . "\n";
                        $parameters .= ManageComplexArg($property, $specs->{"definitions"}{$ref}{"properties"}{$property}{"\$ref"});
                }
		if ( !$isDefined ) {
			if ( $root =~ m/NULL/ ) {
				$parameters .= $property . "|";
			}
			else{
				$parameters .= $root . "\\." . $property . "|";
			}
		}
	}
	return $parameters;
}

#remove var from url (such as {id} or {email}), replace it with a regex matching anything exept "/"
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

#Generate a valid LocationMatch directive for apache from the given URL
sub BuildModsecLocationMatch {
	my ($url) = @_;
	if ( $url =~ m/\{.*\}/ ) {
		$url = &CleanArgFromUrl($url);
	}
	$url = "<LocationMatch \"^" . $url . "\$\">";
	return($url);
}

#Generate a modsec's arg_names rule from given list of argument, basicaly we are checking if the  supplied argument is listed in the spec
sub BuildModsecArgNamesRule {
	my ($arg) = @_;
	$arg =~ s/\|$//;
	my $rule = "SecRule ARGS_NAMES \"!^(?:" . $arg . ")\$\" \"phase:2,t:none,deny,id:'" . &SecRuleIDGen . "',msg:'Unrecognized argument',logdata:%{ARGS_NAMES}\"";
	return $rule;
}

#Generate a modsec's request_method rule from given list of methods extracted from swagger's specifications
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

#build a modsec request header rule to check if the request content-type match the on specified in swagger's endpoint description
sub BuildModsecContentTypeRule {
	my ($contentType) = @_;
	$contentType =~ s/\|$//;
	my $rule = "SecRule REQUEST_HEADERS:Content-Type \"!\@rx (?i)^(";
	$rule .= $contentType;
	$rule .= ")\" \"phase:1,t:none,deny,id:'" . &SecRuleIDGen . "',msg:'Invalid content-type',logdata:%{MATCHED_VAR}\"";
	return $rule;
}

#main routine, extract infos from the downloaded json and call subroutine to build modsec rules
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
			print "\t\t" . BuildModsecReqMethodRule(@methods) . "\n";
			my $paramList = '';
			my $contentTypeList = '';
			foreach my $method (@methods) {
				if ( exists($specs->{"paths"}{$url}{$method}{"parameters"}) ) {
					my @parameters = keys $specs->{"paths"}{$url}{$method}{"parameters"};
					foreach my $parameter (@parameters) {
						#if the argument has a definition we dig into it
						if ( exists($specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"schema"}{"\$ref"}) ) {
#							print "\nD : l'argument " . $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"} . " est defini, sa definition est " . $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"schema"}{"\$ref"} . "\n" ;
							$paramList .= &ManageComplexArg("NULL", $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"schema"}{"\$ref"});
						}
						else {
							$paramList .= $specs->{"paths"}{$url}{$method}{"parameters"}[$parameter]{"name"} . "|";
						}
					}
				}
				#if a content type for input is specified we build the matching rule
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
