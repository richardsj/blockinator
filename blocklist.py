#!/usr/bin/python
"""Program to fetch a blocklist via HTTP"""

import sys
import logging

class BlockList(object):
    """Class to perform basic reading of Sentor blocklist URLs and add them
       to a common data store."""
    data = {}

    def __init__(self):
        """Read and parse configuration to a local object variable."""
        import ConfigParser
        import os

        # Find the configuration file in the same directory at the main script.
        config_file = os.path.join(
            os.path.dirname(sys.argv[0]),
            "blocklist.cfg"
        )
        try:
            self.config = ConfigParser.ConfigParser()
            self.config.readfp(open(config_file))
        except (IOError, ConfigParser.MissingSectionHeaderError), error:
            logging.error(
                "Could not read configuration file %s: %s",
                config_file,
                error
            )
            raise

    def read(self, source):
        """Parse the blocklist from the provided url (source) using a
           CSV parser."""
        import csv

        try:
            # Parse the Sentor Assassin blocklist format
            # (easist to use a CSV parser)
            reader = csv.reader(self.cache(source))
            for line in reader:
                # Fetch the items from the input
                (remote_ip, forwarded_ip, useragent, cookie) = line
                self.add(remote_ip, forwarded_ip, useragent, cookie)
        except csv.Error, error:
            logging.error(
                "There was an error retrieving the blocklist. %s",
                error
            )

    def add(self, remote_ip, forwarded_ip, useragent, cookie):
        """Method to store the remote_ip, forwarded_ip, useragent and cookie
           to the in-memory dictionary."""
        # Store the various items
        if remote_ip not in self.data:
            self.data[remote_ip] = {
                "remote_ip": remote_ip,
                "forwarded_ip": forwarded_ip,
                "useragent": useragent,
                "cookie": cookie
            }
        else:
            logging.debug(
                "%s already exists in blacklist.  Ignoring.",
                remote_ip
            )

    def cache(self, source):
        """Attempt to read from the source URL and store results in a cache
           file, otherwise use the contents of the cache.  If the cache isn't
           usable but the data is still available, return the transient data."""
        import urllib2
        import urlparse
        import os

        # Build some 'handy' variables
        hostname = urlparse.urlparse(source)[1]
        cache_dir = self.config.get("cache", "directory")
        cache_path = os.path.join(cache_dir, "%s.cache" % hostname)

        # Create the caching directory
        if not os.path.exists(cache_dir):
            try:
                os.makedirs(cache_dir)
            except OSError, error:
                logging.warning(
                    "Could not create the caching directory: %s." +
                    "Will attempt to run without a cache.",
                    error
                )

        # Attempt to fetch the data and store it in a cache file
        try:
            input_list = urllib2.urlopen(source)
            raw_data = input_list.read()
            cache_file = open(cache_path, "w+")
            cache_file.write(raw_data)
        except (urllib2.URLError, urllib2.HTTPError), error:
            # Network error.  Warn and use the cached content.
            logging.warning(
                "Reverting to cache file.  There was a problem contacting" +
                "host %s: %s",
                hostname,
                error
            )
            try:
                cache_file = open(cache_path, "r")
            except IOError, error:
                logging.error(
                    "No cache file was available for %s: %s",
                    hostname,
                    error
                )
                raise
        except IOError, error:
            # Cache error, but network succeeded.  Use String IO
            # to return the data.
            import StringIO
            logging.warning(
                "Could not create cache file: %s." +
                "Returning transient data.",
                error
            )
            cache_file = StringIO.StringIO()
            cache_file.write(raw_data)

        # Rewind the file
        cache_file.seek(0)

        # Return the best available data
        return cache_file

    def dump(self):
        """Dump the local datastore out to stdout."""
        for name, val in self.data.iteritems():
            for address in val:
                print "%s: %s" % (name, address)

    def export(self):
        """Output a plaintext blocklist to stdout."""
        for item in self.data.values():
            print "%s,%s,%s,%s" % (
                item["remote_ip"],
                item["forwarded_ip"],
                item["useragent"],
                item["cookie"]
            )
