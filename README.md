# wireshark-sctp_extend
A Wireshark LUA script to display some additional SCTP information

This is a dissector script which adds a new tree to the Wireshark view, _SCTP extended info_. Developed initially to provide relative TSNs (analagous to the TCP dissector's use of relative SEQ).

* **rel_tsn**: relative Transmission Sequence Number
* **rel_tsn_ack**: relative Transmission Sequence Number ACKnowledgement

## Usage:
Copy to your Wireshark plugins folder, on Windows 8 and later this is `C:\Users\<username>\AppData\Roaming\Wireshark\plugins`. You may need to create the folder first.

Now when viewing a capture in Wireshark you'll see an extra line in the protocol list, _SCTP extended info_. These can be filtered and displayed as columns, just like any native Wireshark protocol information.

## Compatibility
Tested on Wireshark 2.0.0 under Windows 8.1. It may work with other OS and versions, if it doesn't submit an issue or pull request.

## Known limitiations:
* None, yet.
