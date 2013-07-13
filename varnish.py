#!/usr/bin/python 
"""Script to create a ACL file for inclusion within Varnish."""

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

def main():
    """Main program loop."""
    block_list = VarnishBlockList()

    block_list.read("http://server1.example.com/default/blocks.txt")
    block_list.read("http://server2.example.com/default/blocks.txt")

    block_list.export()

    sys.exit(0)

if __name__ == "__main__":
    main()
