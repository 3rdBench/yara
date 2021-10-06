## RangeForce YARA SOC Challenge

Create a YARA rule that will scan suspected malware-infected files using the provided malware strings (stored at intel/strings.txt).

Write a script that will read through each malware strings & generate the corresponding YARA rule (to be stored at rules/).


### What is this?

The following is my approach in solving RangeForce's YARA-related SOC challange


### File description

* intel/strings.txt - pre-defined malware strings
* rules/malware.yar - generated YARA rule
* create_rule.py - Python script that reads malware strings & generate corresponding YARA rule

