# Introduction

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by David Cannings (@edeca) <david.cannings@nccgroup.com>

http://www.github.com/nccgroup/yaml2yara

This project is released under the AGPL license.  Please see LICENSE for more information.

# Overview

This repository contains a script that will create custom detection rules from YAML input.

It is used to automatically generate the same rule for multiple pieces of input data, for example:

 * Rules to detect stolen code signing certificates.
 * Rules to detect known vulnerable OLE components in exploit documents.
 * Rules to detect known bad resources (icons, dialogs etc).

This decouples the rule logic and data to match, meaning that bulk rules can be updated easily to optimise them or take advantage of new YARA features.

It was initially designed to generate Yara rules.  However this could easily be expanded to any other format (MAEC, Suricata rules) with new templates.

# Aims

The aims are to:

 * Store useful data in a human readable format.
 * Generate rules with minimal fuss.
 * Produce output which can be fed into your favourite source code management tool (Git, mercurial, etc.).

# Usage

Some sample data files and templates are included in the repository.  Example usage:

    ./generate.py --template authenticode --input sample_data/authenticode/stolen_certs.yaml
    ./generate.py --template office_exploits --input sample_data/office_exploits/ole.yaml
    ./generate.py --template resources --input sample_data/resources/malware.yaml

The output can also be modified with `--tag`, which will add [rule tags](http://yara.readthedocs.io/en/latest/writingrules.html#rule-tags) to each generated rule:

    ./generate.py --template authenticode --tag authenticode --input sample_data/authenticode/stolen_certs.yaml

A `--prefix` option is also available, which will name all rules:

    ./generate.py --template office_exploits --prefix exploit --input sample_data/office_exploits/ole.yaml

Help is available, see `./generate.py --help`.