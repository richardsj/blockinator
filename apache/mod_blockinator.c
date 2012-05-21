/*
 * mod_blockinator for Apache v2.2
 *
 * Author: Scott Wallace <scott@suborbit.com>
 *   Date: March 2012
 *
 * Written for European Directories to integrate traffic
 * blocking based upon recommendations from a Sentor
 * device.
 *
 * The SQLite DB is populated with a Python script that
 * can be found at, 
 * http://svn.eurodir.eu/svn/common/trunk/scripts/blockinator/trunk/
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include <sqlite3.h>
#include <string.h>

module AP_MODULE_DECLARE_DATA blockinator_module;

/*
 * Global variables for use everywhere
 */
sqlite3 *db;
typedef struct {
    const char *basepath;
    const char *db;
} blockinator_cfg_t;

/*
 * Function to build the configuration for the module
 */
static void *create_blockinator_config(apr_pool_t *p, server_rec *s)
{
    /* Allocate some memory using the proper Apache function */
    blockinator_cfg_t *mod_config = apr_pcalloc(p, sizeof(blockinator_cfg_t));

    return mod_config;
}

/*
 * Function to set the configuration item, 'basepath'
 */
static const char *blockinator_set_config_basepath(cmd_parms *parms, void *mconfig, const char *arg)
{
    blockinator_cfg_t *cfg = ap_get_module_config(parms->server->module_config, &blockinator_module);
    cfg->basepath = (char *)arg;
    return NULL;
}

/*
 * Function to set the configuration item, 'db'
 */
static const char *blockinator_set_config_db(cmd_parms *parms, void *mconfig, const char *arg)
{
    blockinator_cfg_t *cfg = ap_get_module_config(parms->server->module_config, &blockinator_module);
    cfg->db = (char *)arg;
    return NULL;
}

/*
 * Main HTTP request handler
 */
static int mod_blockinator_method_handler(request_rec *r)
{
    const char *remote_ip, *forwarded_ip, *useragent, *cookie;
    char *statement;
    char *sqlite3_error;
    sqlite3_stmt *sqlite3_statement;

    /* Capture the relevant information from the inbound request */
    remote_ip = r->connection->remote_ip;
    forwarded_ip = apr_table_get(r->headers_in, "X-Forwarded-For");
    useragent = apr_table_get(r->headers_in, "User-Agent");
    cookie = apr_table_get(r->headers_in, "Cookie");

    /* Build the SQL statement */
    statement = sqlite3_mprintf("SELECT * FROM blocklist WHERE remote_ip = '%q' AND (forwarded_ip = 'ANY' OR forwarded_ip = '%q') AND (useragent = 'ANY' OR useragent = '%q') AND (cookie = 'ANY' OR instr('%q', cookie))", remote_ip, forwarded_ip, useragent, cookie);

    /* Prepare the statement */
    if (sqlite3_prepare_v2(db, statement, BUFSIZ, &sqlite3_statement, NULL) != SQLITE_OK) {
        /* SQLite error.  Allow. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "SQLite error (%s).  Allow traffic from %s by default.", sqlite3_error, remote_ip);
        sqlite3_free(sqlite3_error);

        return DECLINED;
    }

    /* Check for any results. */
    if (sqlite3_step(sqlite3_statement) == SQLITE_ROW) {
        /* SQLite results.  Time to block. */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Blocklist match. (Forwarded_IP: %s, User-Agent: %s, Cookie: %s)", forwarded_ip, useragent, cookie);
        apr_table_set(r->headers_in, "X-Block", "1");
    }

    /* Tidy-up the SQLite way. */
    if (sqlite3_finalize(sqlite3_statement) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "SQLite error freeing the SQLite compile statement (%s).  Possible memory leak.", sqlite3_error);
        sqlite3_free(sqlite3_error);
    }

    return DECLINED;
}

/*
 * Module initialiser
 */
static void mod_blockinator_init_handler(apr_pool_t *p, server_rec *s)
{
    char *sqlite3_error;
    char sqlite3_instr_extension[BUFSIZ];

    /* Read config from module */
    blockinator_cfg_t *cfg = ap_get_module_config(s->module_config, &blockinator_module);

    /* Build the full path to the SQLite instr() extension */
    sprintf(sqlite3_instr_extension, "%s/sqlite_instr/instr.sqlext", cfg->basepath);

    /* Open the SQLite DB */
    if (sqlite3_open_v2(cfg->db, &db, SQLITE_OPEN_READONLY, NULL)) {
        /* Error. */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_blockinator: SQLite error (%s). Could not open database.", sqlite3_errmsg(db));
    }

    /* Load the EDSA SQLite extension for instr() */
    if ((sqlite3_enable_load_extension(db, 1) != SQLITE_OK) ||
        (sqlite3_load_extension(db, sqlite3_instr_extension, 0, &sqlite3_error) != SQLITE_OK)
    ) {
        /* FAIL */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_blockinator: SQLite error (%s). Failed to load the instr() extension.", sqlite3_error);
        sqlite3_free(sqlite3_error);
    } else {
        /* SQLite module successfully loaded. */
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "mod_blockinator: SQLite loaded the instr() extension successfully.");
    }
}

/*
 * Register hooks
 */
static void register_hooks(apr_pool_t *p)
{
    /* Register the module initialiser */
    ap_hook_child_init(mod_blockinator_init_handler, NULL, NULL, APR_HOOK_LAST);

    /* Register the module header parser in the post_read_request phase of Apache */
    ap_hook_post_read_request(mod_blockinator_method_handler, NULL, NULL, APR_HOOK_FIRST);
}

/*
 * Apache configuration directives
 */
static const command_rec mod_blockinator_directives[] = {
    AP_INIT_TAKE1(
        "BlockinatorHome",
        blockinator_set_config_basepath,
        NULL,
        RSRC_CONF,
        "BlockinatorHome (filepath). The base directory of Blockinator."
    ),
    AP_INIT_TAKE1(
        "BlockinatorBlocklistDB",
        blockinator_set_config_db,
        NULL,
        RSRC_CONF,
        "BlockinatorBlocklistDB (filepath). The absolute path of Blockinator blocklist SQLite DB."
    ),
    {NULL}
};

/*
 * Main module code
 */
module AP_MODULE_DECLARE_DATA blockinator_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structures */
    NULL,			/* merge per-directory config structures  */
    create_blockinator_config,	/* create per-server config structures    */
    NULL,			/* merge per-server config structures     */
    mod_blockinator_directives,	/* command handlers                       */
    register_hooks		/* register hooks                         */
};
