#!/usr/bin/env python
from __future__ import print_function
from collections import OrderedDict
from jinja2 import Environment, PackageLoader
from jinja2.exceptions import TemplateNotFound
from binascii import hexlify
import yaml
import sys
import argparse
import os
import re

########
# Author: David Cannings
#   Date: June 2016
#
# Generate cyber cyber detection rules from YAML input.  Useful to 
# create the same rule multiple times with different input.
#
# Sample usages include detecting known bad code signing certificates,
# identifying resources or signaturing exploit docs based on OLE objects.
#
# Released under AGPL, please see Readme.md and LICENSE.
########

def eprint(*args, **kwargs):
    """ Print an error """
    print(*args, file=sys.stderr, **kwargs)


def fatal(msg):
    """ Print a fatal error and quit """
    eprint("[!] {}".format(msg))
    sys.exit(1)
	
	
def clsid_to_hex(data):
    """ Convert a displayed class ID to the hex representation """

    # See: https://support.microsoft.com/en-us/kb/325648
    data = data.replace('-', '')

    hex_str = data[6:8]
    hex_str += data[4:6]
    hex_str += data[2:4]
    hex_str += data[0:2]
    hex_str += data[10:12]
    hex_str += data[8:10]
    hex_str += data[14:16]
    hex_str += data[12:14]
    hex_str += data[16:]
    return hex_str


def to_hex(data):
    """ Helper function, used inside jinja2 templates """
    return hexlify(data.encode("ascii")).decode("ascii")


def add_tags(rules, global_tags):
    """ Loop through all rules and add global tags """

    for name,r in rules.items():
        for tag in global_tags:
            try:
                r['tags'].append(tag)
            except KeyError:
                r['tags'] = [ tag ]
            except AttributeError:
                # TODO: Fix this case by validating all input according to global rules
                eprint("[!] Error in {}: 'tags' should be a list, not string".format(name))
                sys.exit(0)


def main():
    rules = None

    parser = argparse.ArgumentParser(description='Generate rules from YAML input.')
    parser.add_argument('--tag', nargs='*', default=[], help='Tags to add to all rules')
    parser.add_argument('--prefix', type=str, default="", help='prefix all rule names with a string')
    parser.add_argument('--template', type=str, help='template to use', required=True)
    parser.add_argument('--input', type=str, help='input data file', required=True)
    parser.add_argument('--output', type=str, help='output Yara file', required=True)
    args = parser.parse_args()

    # Check input file exists
    if not os.path.isfile(args.input):
        fatal("Input file does not exist: {}".format(args.input))

    # Validate prefix
    if not re.match('^(|[a-zA-Z][a-zA-Z0-9_]+)$', args.prefix):
        fatal("Not a valid name prefix: {}".format(args.prefix))

    # Validate template name
    if not re.match('^[a-z][a-z_]+$', args.template):
        fatal("Not a valid template name: {}".format(args.template))

    # Check template exists
    try:
        env = Environment(loader=PackageLoader('yaml2yara', 'templates'))
        env.filters['to_hex'] = to_hex
        env.filters['clsid_to_hex'] = clsid_to_hex
        template = env.get_template('{}.html'.format(args.template))
    except TemplateNotFound:
        fatal("Template not found: {}".format(args.template))

    with open (args.input, encoding='utf-8', mode='r') as fh:
        rules = yaml.load(fh, Loader=yaml.SafeLoader)

    # SCM friendly output, sort by rule name so that output
    # is consistent between runs.  This minimises diffs where
    # input data has not changed.
    #
    # Note that templates need to sort any dict items they 
    # use (e.g. tags, a list of hashes etc).
    rules_sorted = OrderedDict(sorted(rules.items(), key=lambda t: t[0]))

    # If custom tags were provided add them to every rule.
    if len(args.tag):
        add_tags(rules_sorted, args.tag)

    rules = template.render(data=rules_sorted, prefix=args.prefix)
    with open(args.output, encoding='utf-8', mode="w") as fh:
        fh.write(rules)


if __name__ == "__main__":
    main()