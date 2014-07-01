#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define my_debug(mess) ap_log_error(APLOG_MARK,\
                                 APLOG_ERR,\
                                 0, r->server, mess)
typedef struct {
    char *hmac_secret;
} hmacauth_cfg;

const char* hmacauth_secret_callback(cmd_parms* cmd, void* cfg, const char* arg);
static void* hmacauth_create_conf(apr_pool_t* pool, server_rec* svr);
static void hmacauth_register_hooks(apr_pool_t *p);

static const command_rec cmds[] =
    {
        AP_INIT_TAKE1("HMACAuthSecret", hmacauth_secret_callback, NULL, OR_ALL, "The secret key used for HMAC auth"),
        { NULL }
    };

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA hmacauth_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    hmacauth_create_conf,  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    cmds,                  /* table of config file commands       */
    hmacauth_register_hooks  /* register hooks                      */
};

static void parse_args(const char *args, int *timestamp, char **secret)
{
    char *args_copy;
    char *current_arg;
    char *tokstate = NULL;
    char *key = NULL, *val = NULL;

    if (args == NULL) {
        return;
    }

    args_copy = strdup(args);
    current_arg = apr_strtok(args_copy, "&", &tokstate);

    // first value pair
    key = current_arg;
    val = strchr(key, '=');
    *val++ = 0;

    if (strcmp(key, "timestamp") == 0) {
        *timestamp = atoi(val);
    } else if (strcmp(key, "secret") == 0) {
        *secret = strdup(val);
    }

    while (current_arg = apr_strtok(NULL, "&", &tokstate)) {
        // subsequent value pairs
        key = current_arg;
        val = strchr(key, '=');
        *val++ = 0;

        if (strcmp(key, "timestamp") == 0) {
            *timestamp = atoi(val);
        } else if (strcmp(key, "secret") == 0) {
            *secret = strdup(val);
        }
    }

    free(args_copy);
}

static int hmacauth_handler(request_rec *r)
{
    // table for translating binary to hex
    const char tbl[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    // loop counters when translating
    int i, j;
    // crypto contexts
    const EVP_MD *evp = EVP_md5();
    HMAC_CTX ctx;
    // hmac input buffer
    char input_buffer[64];
    // hmac raw output
    char raw_output[40], hex_output[40];
    // hexadecimal hmac output
    int raw_output_size = sizeof(raw_output);
    // user supplied timestamp
    unsigned int timestamp = -1;
    // user supplied secret
    char *secret = NULL;
    // comparison timestamp
    time_t current_timestamp = time(NULL);
    // configuration context
    hmacauth_cfg* config = ap_get_module_config(r->server->module_config, &hmacauth_module) ;

    // make sure that we're supposed to handle this
    if (!r->handler || strcmp(r->handler, "hmacauth") != 0) {
        return DECLINED;
    }

    // bail out if no secret is set
    if (config->hmac_secret == NULL) {
        ap_rputs("No HMAC secret set", r);
        return 403;
    }

    // parse querystring
    parse_args(r->args, &timestamp, &secret);

    // only continue if the user has supplied a timestamp and secret
    if (timestamp != -1 && secret != NULL) {

        // make sure that the secret is recently generated
        if (abs(current_timestamp - timestamp) > 3600) {
            ap_rputs("Request denied (timestamp)\n", r);
            return 403;
        }

        // prepare hmac input string
        snprintf(input_buffer, sizeof(input_buffer), "%d|%s", timestamp, r->connection->remote_ip);

        // do the hmac rounds
        HMAC_CTX_init(&ctx);
        HMAC_Init(&ctx, config->hmac_secret, strlen(config->hmac_secret), evp);
        HMAC_Update(&ctx, input_buffer, strlen(input_buffer));
        HMAC_Final(&ctx, raw_output, &raw_output_size);
        HMAC_CTX_cleanup(&ctx);

        // convert hmac output to hex notation
        for (i = 0, j = 0; i < raw_output_size; i++) {
            char c = raw_output[i];

            hex_output[j++] = tbl[(c & 0xF0) >> 4];
            hex_output[j++] = tbl[c & 0x0F];
        }
        hex_output[j] = 0;

        // decline to handle if secret matches, i.e. let someone else take care of it
        if (strcasecmp(secret, hex_output) == 0) {
            return DECLINED;
        }
    }

    // in all other cases, emit access denied
    ap_rputs("Request denied (secret)\n", r);
    return 403;
}

static void hmacauth_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(hmacauth_handler, NULL, NULL, APR_HOOK_FIRST);
}

static void* hmacauth_create_conf(apr_pool_t* pool, server_rec* svr)
{
    hmacauth_cfg* cfg = apr_pcalloc(pool, sizeof(hmacauth_cfg));
    cfg->hmac_secret = NULL;
    return cfg;
}

const char* hmacauth_secret_callback(cmd_parms* cmd, void* cfg, const char* arg)
{
    hmacauth_cfg* config = ap_get_module_config(cmd->server->module_config, &hmacauth_module);
    config->hmac_secret = strdup(arg);

    return NULL;
}

