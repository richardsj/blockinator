C{
	#define BLOCKLIST_DB		"/srv/tmp/blocklist.db"

	#include <stdio.h>
	#include <syslog.h>
	#include <sqlite3.h>
	#include <string.h>
	#include <malloc.h>

	char *remote_ip, *forwarded_ip, *useragent;

	sqlite3 *db;

	int sqlite3_init()
	{
		static int init = 0;
		char *sqlite3_error;

		if (!init) {
			/* Open the SQLite DB */
			if (sqlite3_open_v2(BLOCKLIST_DB, &db, SQLITE_OPEN_READONLY, "unix-none")) {
				syslog(LOG_ERR, "SQLite error (%s). Could not open database.", sqlite3_errmsg(db));
			}
			init = 1;
		}
	}

	int resultHandler(void *sp, int argc, char **argv, char **azColName)
	{
		char *sqlite3_error;

		/* 
			argv[0] - number of matches 
			argv[1] - remote_ip from SQL statement
	
			Check that we have valid results and double check IP before blocking
		*/
		if (argc > 0 && atoi(argv[0]) > 0 && strcmp(argv[1], remote_ip) == 0) {
			/* Any results indicate a block */
			syslog(LOG_INFO, "Blocklist match found for %s/%s. (Forwarded_IP: %s, User-Agent: %s)", remote_ip, argv[1], forwarded_ip, useragent);
			VRT_SetHdr(sp, HDR_REQ, "\010X-Block:", remote_ip, vrt_magic_string_end);
		}

		return 0;
	}
}C
