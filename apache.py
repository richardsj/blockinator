#!/usr/bin/python 

import blocklist
import sys

class ApacheBlockList(blocklist.BlockList):
    """New class that extends the main BlockList class for use with Apache."""
    def export(self):
         """Exports the blocklist addresses with use within Apache."""
         print "\tOrder deny,allow"
         for address in self.data.keys():
             print "\tDeny from %s/32" % address
         print "\tAllow from all"

if __name__ == "__main__":
    blocklist = ApacheBlockList()

    blocklist.read("http://server1.example.com/default/blocks.txt")
    blocklist.read("http://server2.example.com/default/blocks.txt")

    blocklist.export()

    sys.exit(0)

