#!/usr/bin/python 
"""Script to create a simple mod_access style list for inclusion within Apache."""

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

def main():
    """Main program loop."""
    block_list = ApacheBlockList()

    block_list.read("http://server1.example.com/default/blocks.txt")
    block_list.read("http://server2.example.com/default/blocks.txt")

    block_list.export()

    sys.exit(0)

if __name__ == "__main__":
    main()
