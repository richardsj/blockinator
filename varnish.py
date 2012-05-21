#!/usr/bin/python 

import blocklist
import sys

class VarnishBlockList(blocklist.BlockList):
    """New class to extend the main BlockList class for implementation with Varnish."""
    def export(self):
         """Exports blocklist addresses for use within Varnish."""
         print "acl block_list {"
         for address in self.data.keys():
             print "\t\"%s\";" % address
         print "}"

if __name__ == "__main__":
    blocklist = VarnishBlockList()

    blocklist.read("http://server1.example.com/default/blocks.txt")
    blocklist.read("http://server2.example.com/default/blocks.txt")

    blocklist.export()

    sys.exit(0)
