#!/bin/bash

PCAP_DIR=../../pcaps
OUTPUT_DIR=../data
KEY=../../ssh_key.pem

# Make output directory
rm -rf $OUTPUT_DIR
mkdir -p $OUTPUT_DIR

# Loop over PCAPs
for PCAP_FILE in $PCAP_DIR/*.pcap ; do

    FILENAME=$(basename -- "$PCAP_FILE")
    DESCRIPTOR="${FILENAME%.*}"
    OUTPUT_FILE=$OUTPUT_DIR/$DESCRIPTOR
    TMP_FILE=$OUTPUT_DIR/$DESCRIPTOR~

    # TSHARK Features to extract: https://www.wireshark.org/docs/dfref/

    # Print full HTTP request URL followed by data (tab-separated)
    tshark -Y http.request -T fields -e http.request.full_uri -e data -r $PCAP_FILE > $OUTPUT_FILE

    # Write signal in output file to tell scanner when to switch from looking for URLs to scan TLS instead 
    echo "BEGINTLS" >> $OUTPUT_FILE

    # Extract decrypted TLS application data and reverse hex dump for easier searching 
    tshark -r $PCAP_FILE -o "tls.keylog_file: $KEY" -x -Y tls > $TMP_FILE
    cat $TMP_FILE | xxd -r >> $OUTPUT_FILE

    rm $TMP_FILE

done