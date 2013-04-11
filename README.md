This is a plugin for SpamAssassin

This plugin saves a copy of messages that hit one or more of the specified 
rules.

As a single message could hit multiple rules, this plugin stores the actual 
message into \<savehits_dir\>/msgs/\<YYYYMMDD\>/\<sha1\> where \<sha1\> is the SHA1 digest 
of the full message including headers.  This also serves to prevent the storage 
of duplicate messages.

Once the message file is stored, each rule that matches the savehits_rule list 
is stored as \<savehits_dir\>/rules/<RULE_NAME>/<YYYYMMDD>/\<symlink\> where \<symlimk\> 
is a symlink to the stored message file.

