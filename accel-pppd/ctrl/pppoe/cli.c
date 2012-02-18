#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "triton.h"
#include "cli.h"
#include "ppp.h"
#include "memdebug.h"

#include "pppoe.h"

static void show_interfaces(void *cli)
{
	struct pppoe_serv_t *serv;
	int i, count;

	cli_send(cli, "interface:   connections:    state:    service-name:\r\n");
	cli_send(cli, "----------------------------------------------------\r\n");

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		count = 0;
		for (i = 0; i < MAX_SERVICE_NAMES && serv->service_names[i]; i++)
			count++;
		cli_sendv(cli, "%9s    %11u    %6s    %9s, %2d\r\n", serv->ifname, serv->conn_cnt, serv->stopping ? "stop" : "active",
		          serv->require_service_name ? "require" : "default", count);
	}
	pthread_rwlock_unlock(&serv_lock);
}

static void show_interface_service_names(const char *ifname, void *cli)
{
	struct pppoe_serv_t *serv;
	int i, found = 0;

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		if (!strcmp(serv->ifname, ifname)) {
			if (serv->service_names[0]) {
				for (i = 0; i < MAX_SERVICE_NAMES && serv->service_names[i]; i++)
					cli_sendv(cli, "%d: %s\r\n", i, serv->service_names[i]);
			} else {
				cli_send(cli, "*\r\n");
			}
			found = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&serv_lock);

	if (!found) {
		cli_sendv(cli, "interface %s not found\r\n", ifname);
	}
}

static void intf_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "pppoe interface add <ifname> - start pppoe server on specified interface\r\n");
	cli_send(client, "pppoe interface del <ifname> - stop pppoe server on specified interface and drop his connections\r\n");
	cli_send(client, "pppoe interface show - show interfaces on which pppoe server started\r\n");
	cli_send(client, "pppoe interface show <ifname> Service-Name - show interface Service-Names\r\n");
	//cli_send(client, "pppoe interface set <ifname> Service-Name <name>[ <name>[ ...]] - set Service-Names to respond on interface\r\n");
}

static int intf_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	if (fields_cnt == 2)
		goto help;

	if (fields_cnt == 3) {
		if (!strcmp(fields[2], "show"))
			show_interfaces(client);
		else
			goto help;

		return CLI_CMD_OK;
	}

	if (fields_cnt == 5) {
		if (!strcmp(fields[2], "show")) {
			if (!strcmp(fields[4], "Service-Name"))
				show_interface_service_names(fields[3], client);
			else
				goto help;
		} else {
			goto help;
		}
		return CLI_CMD_OK;
	}

	if (fields_cnt != 4)
		goto help;

	if (!strcmp(fields[2], "add"))
		pppoe_server_start(fields[3], client);
	else if (!strcmp(fields[2], "del"))
		pppoe_server_stop(fields[3]);
	else
		goto help;
	
	return CLI_CMD_OK;
help:
	intf_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}

//===================================

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "pppoe:\r\n");
	cli_sendv(client, "  active: %u\r\n", stat_active);
	cli_sendv(client, "  delayed PADO: %u\r\n", stat_delayed_pado);
	cli_sendv(client, "  recv PADI: %lu\r\n", stat_PADI_recv);
	cli_sendv(client, "  drop PADI: %lu\r\n", stat_PADI_drop);
	cli_sendv(client, "  sent PADO: %lu\r\n", stat_PADO_sent);
	cli_sendv(client, "  recv PADR(dup): %lu(%lu)\r\n", stat_PADR_recv, stat_PADR_dup_recv);
	cli_sendv(client, "  sent PADS: %lu\r\n", stat_PADS_sent);

	return CLI_CMD_OK;
}

//===================================

static void set_verbose_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set verbose <n> - set verbosity of pppoe logging\r\n");
	cli_send(cli, "pppoe set PADO-delay <delay[,delay1:count1[,delay2:count2[,...]]]> - set PADO delays (ms)\r\n");
	cli_send(cli, "pppoe set Service-Name <name>[ <name> [...]] - set Service-Names to respond\r\n");
	cli_send(cli, "pppoe set Service-Name * - respond with client's Service-Name\r\n");
	cli_send(cli, "pppoe set AC-Name <name> - set AC-Name tag value\r\n");
	cli_send(cli, "pppoe show verbose - show current verbose value\r\n");
	cli_send(cli, "pppoe show PADO-delay - show current PADO delay value\r\n");
	cli_send(cli, "pppoe show Service-Name - show current Service-Names\r\n");
	cli_send(cli, "pppoe show AC-Name - show current AC-Name tag value\r\n");
}

static int show_verbose_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;
	
	cli_sendv(cli, "%i\r\n", conf_verbose);
	
	return CLI_CMD_OK;
}

static int show_pado_delay_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;
	
	cli_sendv(cli, "%s\r\n", conf_pado_delay);
	
	return CLI_CMD_OK;
}

static int show_service_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	int i;

	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;

	if (conf_service_names[0])
		for (i = 0; i < MAX_SERVICE_NAMES && conf_service_names[i]; i++)
			cli_sendv(cli, "%d: %s\r\n", i, conf_service_names[i]);
	else
		cli_send(cli, "*\r\n");

	return CLI_CMD_OK;
}

static int show_ac_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;
	
	cli_sendv(cli, "%s\r\n", conf_ac_name);
	
	return CLI_CMD_OK;
}

static int set_verbose_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 4)
		return CLI_CMD_SYNTAX;
	
	if (!strcmp(f[3], "0"))
		conf_verbose = 0;
	else if (!strcmp(f[3], "1"))
		conf_verbose = 1;
	else
		return CLI_CMD_INVAL;
	
	return CLI_CMD_OK;
}

static int set_pado_delay_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 4)
		return CLI_CMD_SYNTAX;

	if (dpado_parse(f[3]))
		return CLI_CMD_INVAL;

	return CLI_CMD_OK;
}

static int set_service_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	int i;

	if (f_cnt < 4)
		return CLI_CMD_SYNTAX;
	if (f_cnt > MAX_SERVICE_NAMES + 4)
		return CLI_CMD_INVAL;

	for (i = 0; i < MAX_SERVICE_NAMES; i++) {
		if (conf_service_names[i]) {
			_free(conf_service_names[i]);
			conf_service_names[i] = NULL;
		}
	}

	if (f_cnt > 4 || strcmp(f[3], "*") != 0) {
		for (i = 3; i < f_cnt; i++) {
			conf_service_names[i-3] = _strdup(f[i]);
		}
	}

	return CLI_CMD_OK;
}

static int set_ac_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 4)
		return CLI_CMD_SYNTAX;
	
	_free(conf_ac_name);
	conf_ac_name = _strdup(f[3]);
	
	return CLI_CMD_OK;
}
//===================================


static void init(void)
{
	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");
	cli_register_simple_cmd2(intf_exec, intf_help, 2, "pppoe", "interface");
	cli_register_simple_cmd2(set_verbose_exec, set_verbose_help, 3, "pppoe", "set", "verbose");
	cli_register_simple_cmd2(set_pado_delay_exec, NULL, 3, "pppoe", "set", "PADO-delay");
	cli_register_simple_cmd2(set_service_name_exec, NULL, 3, "pppoe", "set", "Service-Name");
	cli_register_simple_cmd2(set_ac_name_exec, NULL, 3, "pppoe", "set", "AC-Name");
	cli_register_simple_cmd2(show_verbose_exec, NULL, 3, "pppoe", "show", "verbose");
	cli_register_simple_cmd2(show_pado_delay_exec, NULL, 3, "pppoe", "show", "PADO-delay");
	cli_register_simple_cmd2(show_service_name_exec, NULL, 3, "pppoe", "show", "Service-Name");
	cli_register_simple_cmd2(show_ac_name_exec, NULL, 3, "pppoe", "show", "AC-Name");
}

DEFINE_INIT(22, init);
