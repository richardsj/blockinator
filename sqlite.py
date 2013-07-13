#!/usr/bin/python 
"""Script to create a SQLite DB from the blocklist data."""

import blocklist
import sys
import logging

if sys.version_info >= (2, 5):
    import sqlite3
else:
    from pysqlite2 import dbapi2 as sqlite3

class SQLiteBlockList(blocklist.BlockList):
    """New class to extend the main BlockList class for implementation with Varnish."""
    def export(self):
        """Exports blocklist criteria to a SQLite file."""

        try:
            database = sqlite3.connect(self.config.get("sqlite", "database"))
            cur = database.cursor()

            cur.execute("CREATE TABLE IF NOT EXISTS blocklist(remote_ip VARCHAR(15), forwarded_ip VARCHAR(15), useragent VARCHAR(256), cookie VARCHAR(1024), PRIMARY KEY(remote_ip))")

            cur.execute("DELETE FROM blocklist")

            for item in self.data.values():
                if item["useragent"] == 'NULL':
                    item["useragent"] = '(null)'
                cur.execute("INSERT INTO blocklist VALUES ('%s', '%s', '%s', '%s')" % (item["remote_ip"], item["forwarded_ip"], item["useragent"], item["cookie"]))
            database.commit()
            cur.close()
        except sqlite3.Error, error:
            logging.error("There was a problem exporting the data to SQLite.  %s", error)

def main():
    """Main program loop."""
    block_list = SQLiteBlockList()

    block_list.read("http://example.com/default/blocks.txt")

    block_list.export()

    sys.exit(0)

if __name__ == "__main__":
    main()
