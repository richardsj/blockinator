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

module AP_MODULE_DECLARE_DATA blockinator_module;

/*
 * Global variables for use everywhere
 */
sqlite3 *db;
typedef struct {
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
    const char *remote_ip, *forwarded_ip, *useragent;
    char *statement;
    sqlite3_stmt *sqlite3_statement;
    int sqlite3_rc;

    /* Capture the relevant information from the inbound request */
    remote_ip = r->connection->remote_ip;
    forwarded_ip = apr_table_get(r->headers_in, "X-Forwarded-For");
    useragent = apr_table_get(r->headers_in, "User-Agent");

    if (forwarded_ip == NULL) {
        forwarded_ip = "(null)";
    }

    if (useragent == NULL) {
        useragent = "(null)";
    }

    /* Build the SQL statement */
    statement = sqlite3_mprintf("SELECT * FROM blocklist WHERE remote_ip = '%q' AND (forwarded_ip = 'ANY' OR forwarded_ip = '%q') AND (useragent = 'ANY' OR useragent = '%q')", remote_ip, forwarded_ip, useragent);

    /* Prepare the statement */
    sqlite3_rc = sqlite3_prepare_v2(db, statement, BUFSIZ, &sqlite3_statement, NULL);
    if (sqlite3_rc != SQLITE_OK) {
        /* SQLite error.  Allow. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "SQLite error (%s).  Allow traffic from %s by default.", sqlite3_errmsg(db), remote_ip);
        return DECLINED;
    }

    /* Check for any results. */
    if (sqlite3_step(sqlite3_statement) == SQLITE_ROW) {
        /* SQLite results.  Time to block. */
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Blocklist match. (Forwarded_IP: %s, User-Agent: %s)", forwarded_ip, useragent);
        apr_table_set(r->headers_in, "X-Block", "1");
    }

    /* Tidy-up the SQLite way. */
    if (sqlite3_finalize(sqlite3_statement) != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "SQLite error freeing the SQLite compile statement (%s).  Possible memory leak.", sqlite3_errmsg(db));
    }

    sqlite3_free(statement);
    return DECLINED;
}

/*
 * Module initialiser
 */
static void mod_blockinator_init_handler(apr_pool_t *p, server_rec *s)
{
    /* Read config from module */
    blockinator_cfg_t *cfg = ap_get_module_config(s->module_config, &blockinator_module);

    /* Open the SQLite DB */
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "Opening mod_blockinator blocklist DB: %s.", cfg->db);
    if (sqlite3_open_v2(cfg->db, &db, SQLITE_OPEN_READONLY, "unix-none")) {
        /* Error. */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_blockinator: SQLite error (%s). Could not open database.", sqlite3_errmsg(db));
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
