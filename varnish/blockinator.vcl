C{
	#define BLOCKINATOR_HOME	"/srv/app/blockinator"
	#define BLOCKLIST_DB		"/srv/tmp/blocklist.db"

	#include <stdio.h>
	#include <syslog.h>
	#include <sqlite3.h>
	#include <string.h>
	#include <malloc.h>

	char *remote_ip, *forwarded_ip, *useragent, *cookie;

	sqlite3 *db;

	int sqlite3_init()
	{
		static int init = 0;
		char *sqlite3_error;

		if (!init) {
			/* Open the SQLite DB */
			if (sqlite3_open_v2(BLOCKLIST_DB, &db, SQLITE_OPEN_READONLY, NULL)) {
				syslog(LOG_ERR, "SQLite error (%s). Could not open database.", sqlite3_errmsg(db));
			}
			init = 1;

			/* Load the EDSA SQLite extension for instr() */
			if ((sqlite3_enable_load_extension(db, 1) != SQLITE_OK) ||
				(sqlite3_load_extension(db, BLOCKINATOR_HOME"/sqlite_instr/instr.sqlext", 0, &sqlite3_error) != SQLITE_OK)
			) {
				syslog(LOG_ERR, "SQLite error (%s).  Failed to load the instr() extension.", sqlite3_error);
				sqlite3_free(sqlite3_error);
            } else {
				syslog(LOG_INFO, "SQLite loaded the instr() extension successfully.");
            }
		}
	}

	int resultHandler(void *sp, int argc, char **argv, char **azColName)
	{
		char *sqlite3_error;

		if (atoi(argv[0]) > 0) {
			/* Any results indicate a block */
			syslog(LOG_INFO, "Blocklist match found for %s. (Forwarded_IP: %s, User-Agent: %s, Cookie: %s)", remote_ip, forwarded_ip, useragent, cookie);
			VRT_SetHdr(sp, HDR_REQ, "\010X-Block:", "1", vrt_magic_string_end);
		}

		return 0;
	}

	char *str_replace(char *input, char *search, char *replace)
	{
		char *string_ptr, *match_ptr;
		int offset = strlen(search);

        char *output = malloc(BUFSIZ);
        memset(output, 0, BUFSIZ);

		if (! input) return output;

        string_ptr = input;

		while (match_ptr = strstr(string_ptr, search)) {
			strncat(output, string_ptr, match_ptr-string_ptr);
			strcat(output, replace);
			string_ptr = match_ptr + offset;
		}
		strcat(output, string_ptr);

		return output;
	}
}C
