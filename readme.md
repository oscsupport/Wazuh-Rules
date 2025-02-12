# Wazuh Rules
This repo is for custom rules, decoders and possibly other Wazuh related item


## Rules
* All files for rules and decoders is to have the same name
* Start with custom_ 
* Update the validate.log file to test and remove all NDA data
* Update the answers.md result with the description from Phase 3
* All rules to be documented with simple comments
* Sort rules in the order high, medium and then low severity


## Resources
* [Decoder](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html)
* [Rules](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
* [Regex](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html)
* Use [this](https://regex101.com/r/nPoEcH/1) page to validate regex while testing

## Rules
* Unifi
    * Port Forward Delete
    * Admin logon 
    * Generic type
    * Catch all