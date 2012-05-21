#include <string.h>
#include <sqlite3ext.h>

SQLITE_EXTENSION_INIT1

/*
** The sqlite3_instr() SQL function returns the location of a substring match.  An
** implementation of MySQL's instr() function.
*/
void sqlite3_instr(sqlite3_context* pContext, int argc, sqlite3_value** argv)
{
    const char *str1 = (const char *) sqlite3_value_text(argv[0]);
    const char *str2 = (const char *) sqlite3_value_text(argv[1]);

    char *p = strstr(str1, str2);
    int nResult = 0;

    if(p != NULL) {
        nResult = p - str1 + 1;
    }

    sqlite3_result_int(pContext, nResult);
}

/* SQLite invokes this routine once when it loads the extension.
** Create new functions, collating sequences, and virtual table
** modules here.  This is usually the only exported symbol in
** the shared library.
*/
int sqlite3_extension_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi)
{
  SQLITE_EXTENSION_INIT2(pApi)
  sqlite3_create_function(db, "instr", 2, SQLITE_ANY, 0, sqlite3_instr, 0, 0);
  return 0;
}
