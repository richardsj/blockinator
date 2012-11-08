C{
	remote_ip = VRT_IP_string(sp, VRT_r_client_ip(sp));
	forwarded_ip = VRT_GetHdr(sp, HDR_REQ, "\020X-Forwarded-For:");
	useragent = VRT_GetHdr(sp, HDR_REQ, "\013User-Agent:");

	char statement[BUFSIZ];
	char *sqlite3_error;


	snprintf(statement, BUFSIZ, "SELECT COUNT(*), remote_ip FROM blocklist WHERE remote_ip = '%s' AND (forwarded_ip = 'ANY' OR forwarded_ip = '%s') AND (useragent = 'ANY' OR useragent = '%s')", remote_ip, forwarded_ip, useragent);

	sqlite3_init();
	if (sqlite3_exec(db, statement, resultHandler, sp, &sqlite3_error) != SQLITE_OK) {
		/* SQLite error.  Allow. */
		syslog(LOG_WARNING, "SQLite error (%s).  Allow traffic from %s by default.", sqlite3_error, remote_ip);
		syslog(LOG_INFO, "SQLite statment: %s", statement);
		sqlite3_free(sqlite3_error);
	}
}C
