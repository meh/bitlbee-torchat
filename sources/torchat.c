/*
 *  torchat.c - TorChat plugin for BitlBee
 *
 *  Copyright (c) 2012 by meh. <meh@paranoici.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
 *  USA.
 */

/*
 *  Some code taken from: skype.c - Skype plugin for BitlBee
 *
 *  Copyright (c) 2007, 2008, 2009, 2010, 2011, 2012 by Miklos Vajna <vmiklos@frugalware.org>
 */

#include <bitlbee/bitlbee.h>
#include <bitlbee/ssl_client.h>
#include <glib/gprintf.h>
#include <poll.h>

#define TORCHAT_DEFAULT_SERVER "localhost"
#define TORCHAT_DEFAULT_PORT   "11110"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

struct torchat_data {
	struct im_connection *ic;

	/* The onion ID of the current account */
	char* id;

	/* The effective file descriptor. We store it here so any function can
	 * write() to it. */
	int fd;

	/* File descriptor returned by bitlbee. we store it so we know when
	 * we're connected and when we aren't. */
	int bfd;

	/* ssl_getfd() uses this to get the file descriptor. */
	void *ssl;

	/* the next groupchat to be assigned an id */
	struct groupchat *created_groupchat;

	/* groupchat for broadcasts */
	struct groupchat *broadcasts;
};

struct torchat_buddy_data {
	struct {
		char *name;
		char *version;
	} client;
};

struct torchat_groupchat_data {
	char* id;
};

typedef void (*torchat_parser)(struct im_connection *ic, char *address, char *line);

static gboolean torchat_valid_address (char* test)
{
	size_t length = strlen(test);
	size_t i;

	// it's either just the id or the id + .onion
	if (length != 16 && length != 22)
		return FALSE;

	if (length == 22 && strcmp(test + 16, ".onion"))
		return FALSE;

	for (i = 0; i < length; i++)
		if (!isalpha(test[i]) && !(isdigit(test[i]) && test[i] != '0' && test[i] != '1' && test[i] != '8' && test[i] != '9'))
			return FALSE;

	return TRUE;
}

static int torchat_write(struct im_connection *ic, char *buf, int len)
{
	struct torchat_data *td = ic->proto_data;
	struct pollfd pfd[1];

	if (!td->ssl)
		return FALSE;

	pfd[0].fd = td->fd;
	pfd[0].events = POLLOUT;

	/* This poll is necessary or we'll get a SIGPIPE when we write() to
	 * td->fd. */
	poll(pfd, 1, 1000);

	if (pfd[0].revents & POLLHUP) {
		imc_logout(ic, TRUE);

		return FALSE;
	}

	ssl_write(td->ssl, buf, len);

	return TRUE;
}

static int torchat_send(struct im_connection *ic, char *fmt, ...)
{
	va_list args;
	char* str;
	int st, length;

	va_start(args, fmt);
	g_vasprintf(&str, fmt, args);
	va_end(args);

	if (getenv("TORCHAT_DEBUG"))
		fprintf(stderr, ">> %s\n", str);

	length = strlen(str);
	
	str[length] = '\n';

	st = torchat_write(ic, str, length + 1);

	g_free(str);

	return st;
}

static struct groupchat *torchat_find_groupchat(struct im_connection *ic, char *id)
{
	struct groupchat *gc;
	struct torchat_groupchat_data *gcd;
	GSList *l;

	for (l = ic->groupchats; l; l = l->next) {
		gc = l->data;
		gcd = gc->data;

		if (!gcd || !gcd->id)
			continue;

		if (!strcmp(gcd->id, id))
			return gc;
	}

	return NULL;
}

static void torchat_parse_latency(struct im_connection *ic, char *address, char* line)
{
	bee_user_t *bu = bee_user_by_handle(ic->bee, ic, address);
	int size = 1;
	char** argv = g_realloc_n(NULL, size, sizeof(char*));

	char **pieces, **pieceptr, *piece;

	pieceptr = pieces = g_strsplit(line, " ", 0);

	while ((piece = *pieceptr++) && strlen(piece)) {
		argv = g_realloc_n(argv, ++size, sizeof(char*));
		argv[size - 2] = piece;
	}

	argv[size - 1] = 0;

	imcb_buddy_action_response(bu, "PING", argv, NULL);

	g_free(argv);
	g_strfreev(pieces);
}

static void torchat_parse_groupchat_create(struct im_connection *ic, char *address, char* line)
{
	struct torchat_data *td = ic->proto_data;
	struct groupchat *gc = td->created_groupchat;
	struct torchat_groupchat_data *gcd;

	if (!gc) {
		gc = imcb_chat_new(ic, line);
		gc->data = g_new0(struct torchat_groupchat_data, 1);

		imcb_chat_add_buddy(gc, ic->acc->user);
	}

	gcd = gc->data;
	gcd->id = g_strdup(line);

	td->created_groupchat = NULL;
}

static void torchat_parse_groupchat_invite(struct im_connection *ic, char *address, char* line)
{
}

static void torchat_parse_groupchat_join(struct im_connection *ic, char *address, char* line)
{
	char *id = strchr(line, ' ') ? g_strndup(line, strchr(line, ' ') - line) : g_strdup(line);
	struct groupchat *gc = torchat_find_groupchat(ic, id);

	if (!gc)
		goto cleanup;

	imcb_chat_add_buddy(gc, address);

cleanup:
	g_free(id);
}

static void torchat_parse_groupchat_joined(struct im_connection *ic, char *address, char* line)
{
}

static void torchat_parse_groupchat_participants(struct im_connection *ic, char *address, char* line)
{
	char *id = g_strndup(line, strchr(line, ' ') - line);
	char *message = g_strdup(strchr(line, ' ') + 1);
	struct groupchat *gc = torchat_find_groupchat(ic, id);
	char **participants, **participantptr, *participant;

	if (!gc)
		goto cleanup;

	participantptr = participants = g_strsplit(message, " ", 0);

	while ((participant = *participantptr++))
		imcb_chat_add_buddy(gc, participant);

	g_strfreev(participants);

cleanup:
	g_free(id);
	g_free(message);
}

static void torchat_parse_groupchat_leave(struct im_connection *ic, char *address, char* line)
{
	char *id = strchr(line, ' ') ? g_strndup(line, strchr(line, ' ') - line) : g_strdup(line);
	char *message = strchr(line, ' ') ? g_strdup(strchr(line, ' ') + 1) : NULL;
	struct groupchat *gc = torchat_find_groupchat(ic, id);

	if (!gc)
		goto cleanup;

	imcb_chat_remove_buddy(gc, address, message);

cleanup:
	g_free(id);

	if (message)
		g_free(message);
}

static void torchat_parse_groupchat_left(struct im_connection *ic, char *address, char* line)
{
}

static void torchat_parse_groupchat_message(struct im_connection *ic, char *address, char* line)
{
	char *id = g_strndup(line, strchr(line, ' ') - line);
	char *message = g_strdup(strchr(line, ' ') + 1);
	struct groupchat *gc = torchat_find_groupchat(ic, id);

	if (!gc)
		goto cleanup;

	imcb_chat_msg(gc, address, message, 0, 0);

cleanup:
	g_free(id);
	g_free(message);
}

static void torchat_parse_groupchat_destroy(struct im_connection *ic, char *address, char* line)
{
	struct groupchat *gc = torchat_find_groupchat(ic, line);
	struct torchat_groupchat_data *gcd;

	if (!gc)
		return;

	gcd = gc->data;

	g_free(gcd->id);
	g_free(gcd);

	imcb_chat_free(gc);
}

static void torchat_parse_broadcast(struct im_connection *ic, char *address, char* line)
{
	struct torchat_data *td = ic->proto_data;
	struct groupchat *gc = td->broadcasts;

	if (gc)
		imcb_chat_msg(gc, "Anonymous", line, 0, 0);
}

static void torchat_parse_typing(struct im_connection *ic, char *address, char* line)
{
	if (!strcmp(line, "start")) {
		imcb_buddy_typing(ic, address, OPT_TYPING);
	} else if (!strcmp(line, "thinking")) {
		imcb_buddy_typing(ic, address, OPT_THINKING);
	} else {
		imcb_buddy_typing(ic, address, 0);
	}
}

static void torchat_parse_authorized(struct im_connection *ic, char *address, char* line)
{
	struct torchat_data *td = ic->proto_data;
	account_t *acc = ic->acc;
	char *name_hint;

	if (line && *line) {
		if (td->id) {
			if (strcmp(td->id, line)) {
				g_free(td->id);

				td->id = g_strdup(line);
			}
		} else {
			td->id = g_strdup(line);
		}

		set_setstr(&acc->set, "id", td->id);
	}

	if (set_getstr(&acc->set, "display_name"))
		torchat_send(ic, "NAME %s", set_getstr(&acc->set, "display_name"));

	imcb_connected(ic);

	if (set_getbool(&acc->set, "broadcasts")) {
		td->broadcasts = imcb_chat_new(ic, "broadcasts");

		name_hint = g_strdup_printf("broadcasts_%s", ic->acc->user);
		imcb_chat_name_hint(td->broadcasts, name_hint);
		g_free(name_hint);

		imcb_chat_topic(td->broadcasts, "Anonymous", "In this channel you can receive and send broadcasts through the torchat network", 0);
		imcb_chat_add_buddy(td->broadcasts, "Anonymous");
		imcb_chat_add_buddy(td->broadcasts, ic->acc->user);
	}
}

static void torchat_parse_connected(struct im_connection *ic, char *address, char* line)
{
	imcb_add_buddy(ic, address, NULL);
	imcb_buddy_status(ic, address, BEE_USER_ONLINE, NULL, NULL);
}

static void torchat_parse_disconnected(struct im_connection *ic, char *address, char* line)
{
	if (!bee_user_by_handle(ic->bee, ic, address))
		return;

	imcb_buddy_status(ic, address, 0, NULL, NULL);
}

static void torchat_parse_remove(struct im_connection *ic, char *address, char *line)
{
	imcb_remove_buddy(ic, address, NULL);
}

static void torchat_parse_status(struct im_connection *ic, char *address, char* line)
{
	if (!strcmp(line, "available"))
		imcb_buddy_status(ic, address, BEE_USER_ONLINE, NULL, NULL);
	else if (!strcmp(line, "away") || !strcmp(line, "xa"))
		imcb_buddy_status(ic, address, BEE_USER_ONLINE | BEE_USER_AWAY, NULL, NULL);
	else if (!strcmp(line, "offline"))
		imcb_buddy_status(ic, address, 0, NULL, NULL);
}

static void torchat_parse_client_name(struct im_connection *ic, char *address, char* line)
{
	bee_user_t *bu = bee_user_by_handle(ic->bee, ic, address);
	struct torchat_buddy_data *bd = bu->data;

	if (bd->client.name) {
		g_free(bd->client.name);
	}

	bd->client.name = g_strdup(line);
}

static void torchat_parse_client_version(struct im_connection *ic, char *address, char* line)
{
	bee_user_t *bu = bee_user_by_handle(ic->bee, ic, address);
	struct torchat_buddy_data *bd = bu->data;

	if (bd->client.version) {
		g_free(bd->client.version);
	}

	bd->client.version = g_strdup(line);
}

static void torchat_parse_name(struct im_connection *ic, char *address, char* line)
{
	if (strlen(line) > 0)
		imcb_rename_buddy(ic, address, line);
	else
		imcb_rename_buddy(ic, address, NULL);
}

static void torchat_parse_description(struct im_connection *ic, char *address, char* line)
{
	imcb_buddy_status_msg(ic, address, line);
}

static void torchat_parse_list(struct im_connection *ic, char *address, char* line)
{
	char **ids, **idptr, *id;

	idptr = ids = g_strsplit(line, " ", 0);

	while ((id = *idptr++) && strlen(id)) {
		imcb_add_buddy(ic, id, NULL);

		torchat_send(ic, "STATUS %s", id);
		torchat_send(ic, "CLIENT %s", id);
		torchat_send(ic, "NAME %s", id);
		torchat_send(ic, "DESCRIPTION %s", id);
	}

	g_strfreev(ids);
}

static void torchat_parse_message(struct im_connection *ic, char *address, char* line)
{
	imcb_buddy_msg(ic, address, line, 0, 0);
}

static gboolean torchat_read_callback(gpointer data, gint fd, b_input_condition cond)
{
	struct im_connection *ic = data;
	struct torchat_data *td = ic->proto_data;
	char* buf = NULL;
	int st, i, times = 0, current = 0;
	char **lines, **lineptr, *line, *tmp, *address;
	static struct parse_map {
		char *k;
		torchat_parser v;
	} parsers[] = {
		{ "AUTHORIZED", torchat_parse_authorized },
		{ "CONNECTED", torchat_parse_connected },
		{ "DISCONNECTED", torchat_parse_disconnected },
		{ "REMOVE", torchat_parse_remove },
		{ "STATUS", torchat_parse_status },
		{ "CLIENT_NAME", torchat_parse_client_name },
		{ "CLIENT_VERSION", torchat_parse_client_version },
		{ "NAME", torchat_parse_name },
		{ "DESCRIPTION", torchat_parse_description },
		{ "LIST", torchat_parse_list },
		{ "MESSAGE", torchat_parse_message },

		// typing extension
		{ "TYPING", torchat_parse_typing },

		// broadcast extension
		{ "BROADCAST", torchat_parse_broadcast },

		// groupchat extension
		{ "GROUPCHAT_CREATE", torchat_parse_groupchat_create },
		{ "GROUPCHAT_INVITE", torchat_parse_groupchat_invite },
		{ "GROUPCHAT_JOIN", torchat_parse_groupchat_join },
		{ "GROUPCHAT_JOINED", torchat_parse_groupchat_joined },
		{ "GROUPCHAT_PARTICIPANTS", torchat_parse_groupchat_participants },
		{ "GROUPCHAT_LEAVE", torchat_parse_groupchat_leave },
		{ "GROUPCHAT_LEFT", torchat_parse_groupchat_left },
		{ "GROUPCHAT_MESSAGE", torchat_parse_groupchat_message },
		{ "GROUPCHAT_DESTROY", torchat_parse_groupchat_destroy },

		// latency extension
		{ "LATENCY", torchat_parse_latency }
	};

	if (!td || !td->ssl || td->fd == -1)
		return FALSE;

	do {
		times   += 1;
		buf      = g_realloc(buf, (times * 256) + 1);
		st       = ssl_read(td->ssl, buf + ((times - 1) * 256), 256);
		current += st;
	} while (st == 256);

	if (st > 0) {
		buf[current] = '\0';
		lineptr = lines = g_strsplit(buf, "\n", 0);

		while ((line = *lineptr++) && strlen(line)) {
			if (getenv("TORCHAT_DEBUG"))
				fprintf(stderr, "<< %s\n", line);

			tmp = NULL;

			if (strchr(line, ' ') && torchat_valid_address(tmp = g_strndup(line, strchr(line, ' ') - line))) {
				address = tmp;
				line    = line + strlen(address) + 1;
			} else {
				address = NULL;
			}

			for (i = 0; i < ARRAY_SIZE(parsers); i++) {
				if (!strncmp(line, parsers[i].k, strlen(parsers[i].k))) {
					parsers[i].v(ic, address, line + strlen(parsers[i].k) + 1);
					break;
				}
			}

			if (tmp)
				g_free(tmp);
		}

		g_strfreev(lines);
	} else {
		ssl_disconnect(td->ssl);

		g_free(buf);

		td->fd  = -1;
		td->ssl = NULL;

		imcb_error(ic, "Error while reading from server");
		imc_logout(ic, TRUE);

		return FALSE;
	}

	g_free(buf);

	return TRUE;
}

static void torchat_chat_msg(struct groupchat *gc, char *message, int flags)
{
	struct im_connection *ic = gc->ic;
	struct torchat_groupchat_data *gcd = gc->data;
	char **lines, **lineptr, *line;

	if (!strcmp(gc->title, "broadcasts")) {
		torchat_send(ic, "BROADCAST %s", message);
	} else {
		if (!gcd->id)
			return;

		lineptr = lines = g_strsplit(message, "\n", 0);

		while ((line = *lineptr++))
			torchat_send(ic, "GROUPCHAT_MESSAGE %s %s", gcd->id, line);

		g_strfreev(lines);
	}
}

static void torchat_chat_invite(struct groupchat *gc, char *who, char *message)
{
	struct im_connection *ic = gc->ic;
	struct torchat_data *td = ic->proto_data;
	struct torchat_groupchat_data *gcd = gc->data;

	if (!gcd->id) {
		td->created_groupchat = gc;

		torchat_send(ic, "GROUPCHAT_INVITE %s", who);
	} else {
		torchat_send(ic, "GROUPCHAT_INVITE %s %s", gcd->id, who);
	}
}

static void torchat_chat_leave(struct groupchat *gc)
{
	struct im_connection *ic = gc->ic;
	struct torchat_groupchat_data *gcd = gc->data;

	if (!gcd->id)
		return;

	torchat_send(ic, "GROUPCHAT_LEAVE %s", gcd->id);
}

static struct groupchat *torchat_chat_with(struct im_connection *ic, char *who)
{
	struct torchat_data *td = ic->proto_data;
	struct groupchat *gc = imcb_chat_new(ic, who);

	td->created_groupchat = gc;
	gc->data = g_new0(struct torchat_groupchat_data, 1);

	torchat_send(ic, "GROUPCHAT_INVITE %s", who);

	return gc;
}

struct groupchat *torchat_chat_join(struct im_connection *ic, const char *room, const char *nick, const char *password, set_t **sets)
{
	struct groupchat *gc = imcb_chat_new(ic, room);

	gc->data = g_new0(struct torchat_groupchat_data, 1);

	return gc;
}

static int torchat_send_typing(struct im_connection *ic, char *who, int typing)
{
	if (typing & OPT_TYPING) {
		torchat_send(ic, "TYPING %s start", who);
	} else if (typing & OPT_THINKING) {
		torchat_send(ic, "TYPING %s thinking", who);
	} else {
		torchat_send(ic, "TYPING %s stop", who);
	}

	return 1;
}

static void torchat_add_deny(struct im_connection *ic, char *who)
{
}

static void torchat_rem_deny(struct im_connection *ic, char *who)
{
}

static void torchat_add_permit(struct im_connection *ic, char *who)
{
	torchat_send(ic, "ALLOW %s", who);
}

static void torchat_rem_permit(struct im_connection *ic, char *who)
{
	torchat_send(ic, "BLOCK %s", who);
}

static void torchat_buddy_data_add(bee_user_t *bu)
{
	bu->data = g_new0(struct torchat_buddy_data, 1);
}

static void torchat_buddy_data_free(bee_user_t *bu)
{
	struct torchat_buddy_data *bd = bu->data;

	if (bd->client.name)
		g_free(bd->client.name);

	if (bd->client.version)
		g_free(bd->client.version);

	g_free(bd);
}

static GList *torchat_buddy_action_list(bee_user_t *bu)
{
	static GList *ret = NULL;
	
	if (ret == NULL) {
		static const struct buddy_action ba[] = {
			{ "VERSION", "Get the client the buddy is using" },
			{ "PING",    "Get the client latency" },
			{ NULL, NULL }
		};
		
		ret = g_list_prepend(ret, (void*) ba + 0);
	}
	
	return ret;
}

static void *torchat_buddy_action(struct bee_user *bu, const char *action, char * const args[], void *data)
{
	struct torchat_buddy_data *bd = bu->data;
	struct im_connection *ic = bu->ic;

	if (!strcmp(action, "VERSION") && bd->client.name) {
		char *tmp = g_strdup_printf("%s %s", bd->client.name, bd->client.version);
		char * const argv[] = { tmp, NULL };

		imcb_buddy_action_response(bu, action, argv, NULL);

		g_free(tmp);
	}
	else if (!strcmp(action, "PING")) {
		char * const * arg = args;
		GString *string = g_string_new(NULL);

		while (*arg) {
			string = g_string_append(string, " ");
			string = g_string_append(string, *arg);

			arg = arg + 1;
		}

		torchat_send(ic, "LATENCY %s %s", bu->handle, string->str + 1);
	}

	return NULL;
}

static void torchat_remove_buddy(struct im_connection *ic, char *who, char *group)
{
	torchat_send(ic, "REMOVE %s", who);
}

static void torchat_add_buddy(struct im_connection *ic, char *who, char *group)
{
	torchat_send(ic, "ADD %s", who);
}

static GList *torchat_away_states(struct im_connection *ic)
{
	static GList *l = NULL;

	if (l == NULL) {
		l = g_list_append(l, "away");
		l = g_list_append(l, "extended away");
	}

	return l;
}

static void torchat_set_away(struct im_connection *ic, char *state, char *message)
{
	if (state == NULL) {
		torchat_send(ic, "STATUS available");
		
		if (message)
			torchat_send(ic, "DESCRIPTION %s", message);
		else
			torchat_send(ic, "DESCRIPTION");
	}
	else {
		torchat_send(ic, "STATUS %s", (!strcmp(state, "extended away")) ? "xa" : state);

		if (message)
			torchat_send(ic, "DESCRIPTION %s", message);
	}
}

static void torchat_get_info(struct im_connection *ic, char *who)
{
	bee_user_t *bu = bee_user_by_handle(ic->bee, ic, who);
	struct torchat_buddy_data *bd = bu->data;

	if (bd->client.name)
		imcb_log(ic, "%s - client - %s %s", who, bd->client.name, bd->client.version);

	if (bu->fullname)
		imcb_log(ic, "%s - name - %s", who, bu->fullname);

	if (bu->status_msg)
		imcb_log(ic, "%s - description - %s", who, bu->status_msg);
}

static int torchat_buddy_msg(struct im_connection *ic, char *who, char *message, int flags)
{
	char **lines, **lineptr, *line;
	int st = 0;

	lineptr = lines = g_strsplit(message, "\n", 0);

	while ((line = *lineptr++))
		st += torchat_send(ic, "MESSAGE %s %s", who, line);

	g_strfreev(lines);

	return st;
}

static void torchat_logout(struct im_connection *ic)
{
	struct torchat_data *td = ic->proto_data;
	struct groupchat *gc;
	struct torchat_groupchat_data *gcd;

	torchat_send(ic, "STATUS offline");
	
	if (td->id)
		g_free(td->id);

	if (td->ssl)
		ssl_disconnect(td->ssl);

	g_free(td);

	while (ic->groupchats) {
		gc = ic->groupchats->data;
		gcd = gc->data;

		if (gcd) {
			if (gcd->id)
				g_free(gcd->id);

			g_free(gcd);
		}

		imcb_chat_free(gc);
	}

	ic->proto_data = NULL;
}

static gboolean torchat_start_stream(struct im_connection *ic)
{
	struct torchat_data *td = ic->proto_data;

	if (!td)
		return FALSE;

	if (td->bfd <= 0)
		td->bfd = b_input_add(td->fd, B_EV_IO_READ, torchat_read_callback, ic);

	return torchat_send(ic, "PASS %s", ic->acc->pass) &&
	       torchat_send(ic, "STATUS available") &&
	       torchat_send(ic, "LIST");
}

static gboolean torchat_connected_ssl(gpointer data, int returncode, void *source, b_input_condition cond)
{
	struct im_connection *ic = data;
	struct torchat_data *td = ic->proto_data;

	if (!source) {
		td->ssl = NULL;
		imcb_error(ic, "Could not connect to server");
		imc_logout(ic, TRUE);

		return FALSE;
	}

	imcb_log(ic, "Connected to server, logging in");

	return torchat_start_stream(ic);
}

static gboolean torchat_connected(gpointer data, gint fd, b_input_condition cond)
{
	struct im_connection *ic = data;
	struct torchat_data *td = ic->proto_data;
	account_t *acc = ic->acc;

	write(fd, "STARTTLS\n", 9);
	td->ssl = ssl_starttls(fd, set_getstr(&acc->set, "server"), FALSE, torchat_connected_ssl, ic);

	return TRUE;
}

static void torchat_login(account_t *acc)
{
	struct im_connection *ic = imcb_new(acc);
	struct torchat_data *td = g_new0(struct torchat_data, 1);

	ic->proto_data = td;

	imcb_log(ic, "Connecting");
	td->fd = proxy_connect(set_getstr(&acc->set, "server"), set_getint(&acc->set, "port"), torchat_connected, ic);

	td->ic = ic;
}

static char *torchat_set_display_name(set_t *set, char *value)
{
	account_t *acc = set->data;
	struct im_connection *ic = acc->ic;
	struct torchat_data *td;

	if (!ic)
		return value;

	td = ic->proto_data;

	if (td->ssl)
		torchat_send(ic, "NAME %s", value);

	return value;
}

static char *torchat_dont_set(set_t *set, char *value)
{
	account_t *acc = set->data;
	struct im_connection *ic = acc->ic;
	struct torchat_data *td = ic->proto_data;

	return g_strdup(td->id);
}

static void torchat_init(account_t *acc)
{
	set_t *s;

	s = set_add(&acc->set, "server", TORCHAT_DEFAULT_SERVER, set_eval_account, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;

	s = set_add(&acc->set, "port", TORCHAT_DEFAULT_PORT, set_eval_int, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;

	s = set_add(&acc->set, "id", NULL, torchat_dont_set, acc);
	s->flags |= SET_NOSAVE;

	s = set_add(&acc->set, "display_name", NULL, torchat_set_display_name, acc);

	s = set_add(&acc->set, "broadcasts", "false", set_eval_bool, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;

	acc->flags |= ACC_FLAG_AWAY_MESSAGE | ACC_FLAG_STATUS_MESSAGE;
}

void init_plugin(void)
{
	struct prpl *ret = g_new0(struct prpl, 1);

	ret->name = "torchat";
	ret->login = torchat_login;
	ret->init = torchat_init;
	ret->logout = torchat_logout;
	ret->buddy_msg = torchat_buddy_msg;
	ret->handle_cmp = g_strcasecmp;
	ret->away_states = torchat_away_states;
	ret->set_away = torchat_set_away;
	ret->get_info = torchat_get_info;
	ret->add_buddy = torchat_add_buddy;
	ret->remove_buddy = torchat_remove_buddy;
	ret->buddy_action = torchat_buddy_action;
	ret->buddy_action_list = torchat_buddy_action_list;
	ret->buddy_data_add = torchat_buddy_data_add;
	ret->buddy_data_free = torchat_buddy_data_free;
	ret->add_permit = torchat_add_permit;
	ret->rem_permit = torchat_rem_permit;
	ret->add_deny = torchat_add_deny;
	ret->rem_deny = torchat_rem_deny;
	ret->send_typing = torchat_send_typing;
	ret->chat_msg = torchat_chat_msg;
	ret->chat_invite = torchat_chat_invite;
	ret->chat_leave = torchat_chat_leave;
	ret->chat_with = torchat_chat_with;
	ret->chat_join = torchat_chat_join;

	register_protocol(ret);
}
