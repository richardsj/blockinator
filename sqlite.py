#!/usr/bin/python 

import blocklist
import sys
import logging

if sys.version_info >= (2,5):
    import sqlite3
else:
    from pysqlite2 import dbapi2 as sqlite3

class SQLiteBlockList(blocklist.BlockList):
    """New class to extend the main BlockList class for implementation with Varnish."""
    def export(self):
         """Exports blocklist criteria to a SQLite file."""

         try:
             db = sqlite3.connect(self.config.get("sqlite", "database"))
             cur = db.cursor()

             cur.execute("CREATE TABLE IF NOT EXISTS blocklist(remote_ip VARCHAR(15), forwarded_ip VARCHAR(15), useragent VARCHAR(256), cookie VARCHAR(1024), PRIMARY KEY(remote_ip))")

             cur.execute("DELETE FROM blocklist")

             for key,item in self.data.iteritems():
                 cur.execute("INSERT INTO blocklist VALUES ('%s', '%s', '%s', '%s')" % (item["remote_ip"], item["forwarded_ip"], item["useragent"], item["cookie"]))
             db.commit()
             cur.close()
         except Exception, e:
             logging.error("There was a problem exporting the data to SQLite.  %s" % e)

if __name__ == "__main__":
    blocklist = SQLiteBlockList()

    blocklist.read("http://example.com/default/blocks.txt")

    blocklist.export()

    sys.exit(0)
