#  File Audit System

For this implementation in Swift, I've choosen to keep it simple w.r.t. the types
of events supported: open, close, write, unlink, rename. I did not find a read
event.

There is no configuration, just a simple UI to select the folder to monitor.

The implementation saves events as individual CSV records in the FileAuditSystem.txt
file, in the user's Documents folder.

Requirements for running it:

* In System Preferences, Security & Privacy, Privacy Tab, select Full Disk Access
and check FileAuditSystem.
