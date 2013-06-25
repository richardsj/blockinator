# Compilation

1. Ensure the SQLite development libraries (sqlite-devel) are installed.
2. Either run the `build_from_scratch.sh` script or run the following commands:

    ```Shell
    libtoolize
    aclocal
    autoconf
    automake -a
    ./configure --with-apache=<Apache location>
    make CFLAGS=-lsqlite3
    ```

# Installation

1. Activate in Apache using:
    * (automatic) Using APXS:

        ```Shell
        apxs -i -a -n blockinator libmodblockinator.la
        ```

    _*or*_
    * (manual) Add the following commands to the Apache configuration:

        ```ApacheConf        
        LoadModule blockinator_module modules/libmodblockinator.so
        ```

2. Configure mod_blockinator by adding the following lines in the appropriate location(s):
    1. Define where the blocklist DB can be found:

        ```ApacheConf
        <IfModule blockinator_module>
            BlockinatorBlocklistDB    /path/to/blocklist.db
        </IfModule>
        ```

    2. Create a mod_rewrite rule to block requests, if matched:

        ```ApacheConf
        RewriteCond %{HTTP:X-Block}	1
        RewriteRule .			-  [R=403,L]
        ```

3. Create the SQLite DB:
    1. Start SQLite3 on a new file:

        ```Shell
        sqlite3 /path/to/blocklist.db
        ```

    2. Run the following SQL:

        ```SQL
        CREATE TABLE IF NOT EXISTS blocklist(remote_ip VARCHAR(15), forwarded_ip VARCHAR(15), useragent VARCHAR(256), cookie VARCHAR(1024), PRIMARY KEY(remote_ip));
        ```

    3. (optional) Insert some test data:

        e.g. Block requests from IP address 1.2.3.4

        ```SQL
        INSERT INTO blocklist VALUES("1.2.3.4", "ANY", "ANY", "ANY");
        ```

4. Restart Apache
