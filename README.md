# Packet Scanner

*Developed to facilitate a privacy analysis of a Tinylogics Memo Box. Performed as part of COSC 89.26 Security and Privacy in the Lifecycle of IoT in Consumer Envrionments (SPLICE) at Dartmouth College during fall 2020.*

## Instructions

This packet scanner reads specially-formatted binary files from a directory and scans their contents for both image data and words found in provided dictionaries. It is called as follows: `packet-scanner -d <dictionary>... -i <input directory> -o <output directory>`.

To get started:
* Generate a `data/` input directory by running a Bash script from the `scripts/` directory.
    * The `extract_pcap_data.sh` script generates input packet files from PCAPs.
* Run `packet-scanner` on the desired data with the desired dictionaries 
* Any found images will be saved in the output directory

## Packet File Format

The scanned packets must have the following format:

```
<url1> <hex request1 data>
<url2> <hex request2 data>
<urlN> <hex requestN data>
BEGINTLS
<binary data>
```

```
https://www.example.com 01234deadbeef
BEGINTLS

.4/{m?.C.?.?K{?'?P..???..........?..?.???.???D?K??5??P?V?(.?y"?
5?VZ??6??|6?3G??;.?Y.?..U....k??}hellothere..??."......?+?
,??/?0??.?..?.?..?.?./.5...?..............
...............................................3.&.$...8Q./?...s.???.LK?.?5???
??W?..E.-.....+..............?..................P.?@F|......;...7.._
??nm.?H?.??1?Q?P..???0ZVT\??).?/.......?..............n...j..g..d0?.`0?.H?.....
..?.0o?c?00
```

The packet file name will be used as a descriptive label in the program.