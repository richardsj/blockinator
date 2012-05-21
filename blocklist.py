#!/usr/bin/python

import sys
import logging

class BlockList:
    """Class to perform basic reading of Sentor blocklist URLs and add them to a common data store."""
    data = {}

    def __init__(self):
        """Read and parse configuration to a local object variable."""
        import ConfigParser
        import os

        # Find the configuration file in the same directory at the main script.
        config_file = os.path.join(os.path.dirname(sys.argv[0]), "blocklist.cfg")
        try:
            self.config = ConfigParser.ConfigParser()
            self.config.readfp(open(config_file))
        except Exception, e:
            logging.error("Could not read configuration file %s: %s" % (config_file, e))
            raise

    def read(self, source):
        """Parse the blocklist from the provided url (source) using a CSV parser."""
        import csv

        try:
            # Parse the Sentor Assassin blocklist format (easist to use a CSV parser)
            reader = csv.reader(self.cache(source))           
            for line in reader:
                # Fetch the items from the input
                (remote_ip, forwarded_ip, useragent, cookie) = line
                self.add(remote_ip, forwarded_ip, useragent, cookie)
        except Exception, e:
             logging.error("There was an error retrieving the blocklist. %s" % e)

    def add(self, remote_ip, forwarded_ip, useragent, cookie):
            # Store the various items
            if remote_ip not in self.data:
                self.data[remote_ip] = { "remote_ip": remote_ip, "forwarded_ip": forwarded_ip, "useragent": useragent, "cookie": cookie }
            else:
                logging.debug("%s already exists in blacklist.  Ignoring." % remote_ip)

    def cache(self, source):
        """Attempt to read from the source URL and store results in a cache file, otherwise use the contents of the cache.  If the cache isn't usable but the data is still available, return the transient data."""
        import urllib2
        import urlparse
        import os
     
        # Build some 'handy' variables 
        hostname = urlparse.urlparse(source)[1]
        cache_dir = self.config.get("cache", "directory")
        cache_path = os.path.join(cache_dir, "%s.cache" % hostname )

        # Create the caching directory
        if not os.path.exists(cache_dir):
            try:
                os.makedirs(cache_dir)
            except:
                logging.warning("Could not create the caching directory.  Will attempt to run without a cache.")

        # Attempt to fetch the data and store it in a cache file
        try:
            list = urllib2.urlopen(source)
            raw_data = list.read()
            cache_file = open(cache_path, "w+")
            cache_file.write(raw_data)

            # Rewind the file
            cache_file.seek(0)
        except (urllib2.URLError, urllib2.HTTPError), e:
            # Network error.  Warn and use the cached content.
            logging.warning("Reverting to cache file.  There was a problem contacting host %s: %s" % (hostname, e))
            try:
                cache_file = open(cache_path, "r")
            except IOError, e:
                logging.error("No cache file was available for %s." % hostname)
                raise
        except Exception, e:
            # Cache error, but network succeeded.  Use String IO to return the data.
            import StringIO
            logging.warning("Could not create cache file: %s.  Returning transient data." % e)
            cache_file = StringIO.StringIO()
            cache_file.write(raw_data)

            # Rewind the file
            cache_file.seek(0)

        # Return the best available data
        return cache_file

    def dump(self):
        """Dump the local datastore out to stdout."""
        for list,val in self.data.iteritems():
            for address in val:
                print "%s: %s" % (list, address)

    def export(self):
        """Output a plaintext blocklist to stdout."""
        for key,item in self.data.iteritems():
            print "%s,%s,%s,%s" % (item["remote_ip"], item["forwarded_ip"], item["useragent"], item["cookie"])
