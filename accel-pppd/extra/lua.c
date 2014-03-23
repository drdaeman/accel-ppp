#include <string.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <pthread.h>

#include "events.h"
#include "triton.h"
#include "log.h"
#include "cli.h"


static lua_State *Lua;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


static int lf_print(lua_State *L) {
    int nargs, i;

        nargs = lua_gettop(L);
        for (i = 1; i <= nargs; i++) {
            const char* msg = lua_tostring(L, 1);
            log_debug("%s\n", msg);
        }

    return 0;
}


static void set_lua_global_field(const char* package, const char *field, const char* value)
{
    pthread_mutex_lock(&lock);
        lua_getglobal(Lua, package);
        lua_pushstring(Lua, value);
        lua_setfield(Lua, -2, field);
        lua_pop(Lua, 1);
    pthread_mutex_unlock(&lock);
}


static void reload_config(void)
{
    const char* opt;

    opt = conf_get_opt("lua", "path");
    if (opt) {
        set_lua_global_field("package", "path", opt);
    }

    opt = conf_get_opt("lua", "cpath");
    if (opt) {
        set_lua_global_field("package", "cpath", opt);
    }

    opt = conf_get_opt("lua", "script");
    if (opt) {
        if (luaL_dofile(Lua, opt)) {
            luaL_error(Lua, "Error running script: %s", lua_tostring(Lua, -1));
        }
    }
}


static void cli_lua_help(char* const *f, int f_cnt, void *cli)
{
    cli_send(cli, "lua load <filename>  - loads and executes Lua script\r\n");
}


static int cli_lua(const char *cmd, char * const *f, int f_cnt, void *cli)
{
    int ret = CLI_CMD_OK;
    if (f_cnt != 3)
        return CLI_CMD_SYNTAX;

    pthread_mutex_lock(&lock);
        if (luaL_dofile(Lua, f[2])) {
            cli_send(cli, "command failed\r\n");
            log_debug("failed script %s\n", f[2]);
            ret = CLI_CMD_FAILED;
        } else {
            cli_send(cli, "command suceeded\r\n");
            log_debug("ran script %s\n", f[2]);
        }
    pthread_mutex_unlock(&lock);

    return ret;
}


static void load_config(void)
{
    reload_config();
}


static void init(void)
{
    Lua = luaL_newstate();
    luaL_openlibs(Lua);

    lua_newtable(Lua);
        lua_pushcfunction(Lua, lf_print);
        lua_setfield(Lua, -2, "print");
    lua_setglobal(Lua, "pppd");

    load_config();
    triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_config);

    cli_register_simple_cmd2(&cli_lua, cli_lua_help, 1, "lua");
    log_debug("Lua initialized.\n");
}

DEFINE_INIT(200, init);
