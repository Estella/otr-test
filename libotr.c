/*
    DO NOT USE FOR PRODUCTION!
    This is a simple test client for the OTR reference implementation.

    Copyright (C) 2016, 2017  Alexander Senier <alexander.senier@tu-dresden.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>
#include <netdb.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <readline/readline.h>

#include <libotr/context.h>
#include <libotr/tlv.h>
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/privkey.h>

#define LOG(fmt,...) { printf ("[34m[%s][0m " fmt "\n", __func__, ##__VA_ARGS__); }
#define HANDLE_GCRY_ERROR(err,fmt,rv,...) { if (err) { printf ("[%s] " fmt " %s\n", __func__, ##__VA_ARGS__, gcry_strerror (err)); return rv; }};

int sock;
OtrlUserState us;

char *account   = NULL;
char *recipient = NULL;

static OtrlPolicy op_policy
    (void *opdata __attribute__((unused)),
     ConnContext *context __attribute__((unused)))
{
    return OTRL_POLICY_ALWAYS;
}

void op_inject
    (void *opdata __attribute__((unused)),
     const char *accountname,
     const char *protocol,
     const char *recipient,
     const char *message)
{
    int rv = -1;
    size_t len;
    char *buffer;

    LOG ("Inject message for recipient=%s, account=%s, protocol=%s: %s", recipient, accountname, protocol, message);

    len = strlen (message) + 1;
    buffer = malloc (len + 2);

    printf ("Len: %hu", htons (len));

    unsigned int l = htons (len);
    buffer[0] = (char)(l && 0xf);
    buffer[1] = (char)(l >> 8);
    strncpy (buffer+2, message, len);

    rv = write (sock, buffer, len + 2);
    if (rv < 0)
    {
        free (buffer);
        warn ("op_inject");
    }
    free (buffer);
    LOG ("Sent message of length %lu", len);
}

void gone_secure
    (void *opdata __attribute__((unused)),
     ConnContext *context __attribute__((unused)))
{
    LOG ("Gone secure");
}

int max_message_size
    (void *opdata __attribute__((unused)),
     ConnContext *context __attribute__((unused)))
{
  return 10000;
}

const char* otr_error_message
    (void *opdata __attribute__((unused)),
     ConnContext *context __attribute__((unused)),
     OtrlErrorCode err_code __attribute__((unused)))
{
    LOG ("OTR error message");
    return NULL;
}

void otr_error_message_free
    (void *opdata __attribute__((unused)),
     const char *err_msg)
{
  free((char*)err_msg);
}

void handle_msg_event
    (void *opdata __attribute__((unused)),
     OtrlMessageEvent msg_event,
     ConnContext *context __attribute__((unused)),
     const char *message __attribute__((unused)),
     gcry_error_t err __attribute__((unused)))
{
    LOG ("Handle message event: %d (err=%u)", msg_event, err);
}

static OtrlMessageAppOps ops =
{
    op_policy,
    NULL,
    NULL,
    op_inject,
    NULL,
    NULL,
    NULL,
    gone_secure,
    NULL,
    NULL,
    max_message_size,
    NULL,
    NULL,
    NULL,
    otr_error_message,
    otr_error_message_free,
    NULL,
    NULL,
    NULL,
    handle_msg_event,
    NULL,
    NULL,
    NULL,
    NULL
};

int dispatch_message (char *message)
{
    int result;
    char *new_message;

    LOG ("Dispatching: %s", message);
    result = otrl_message_receiving
        (us,
         &ops,
         NULL,
	     account,                   // accountname
         "local",                   // protocol
         recipient,                 // sender
         message,                   // message
         &new_message,              // newmessagep
         NULL,                      // tlvsp
         NULL,                      // contextp
         NULL,                      // add_appdata
         NULL);                     // data
    
    if (result == 1)
    {
        LOG ("Internal message");
        return 0;
    }

    if (result == 0)
    {
        if (new_message)
        {
            LOG ("Protected message: %s", new_message);
            otrl_message_free (new_message);
        } else
        {
            LOG ("Plain message: %s", message);
        }
    }
    return 0;
};

int read_buffer (int fd, char *buf, ssize_t *bufsize)
{
    ssize_t nread = 0, total = 0;

    for (;;)
    {
        nread = read (fd, buf + total, *bufsize);
        if (nread < 0)
        {
            return -1;
        }

        total += nread;
        *bufsize -= nread;

        if (*bufsize == 0 || nread == 0 || buf[total-1] == 0)
        {
            *bufsize = total;    
            return nread != 0;
        }
    };
}


void *network_reader (void *unused __attribute__((unused)))
{
    char line[1000];
    ssize_t nread;
    int rv;

    LOG ("Started");

    do
    {
        nread = sizeof (line);
        rv = read_buffer (sock, line, &nread);
        if (rv > 0)
        {
            rv = dispatch_message (line);
        };
    } while (rv >= 0);

    LOG ("DONE");

    return NULL; 
}

void
help (void)
{
    errx (1, "{-c|-s} -a <account> -r <recipient> -H <host> -P <port> [-h]");
}

int
main (int argc, char **argv)
{
    int opt, client, server, port, rv, s, flag;
    char *hostname, *new_message;
    struct hostent *host;
    struct sockaddr_in addr;
    char *line;
    pthread_t cr;
    socklen_t socklen;
    gcry_error_t result;

    client = 0;
    server = 0;
    port = 0;
    hostname = NULL;
    host = NULL;

    rv = sigaction (SIGPIPE, NULL, NULL);
    if (rv < 0)
    {
        err (1, "sigaction");
    }

    while ((opt = getopt (argc, argv, "a:r:scP:H:h")) != -1)
    {
        switch (opt)
        {
            case 'a': account = strdup (optarg); break;
            case 'r': recipient = strdup (optarg); break;
            case 's': server = 1; break;
            case 'c': client = 1; break;
            case 'P': port = atoi (optarg); break;
            case 'H': hostname = strdup (optarg); break;
            case 'h': help(); break;
            case '?': errx (1, "Invalid argument");
        }
    }

    if (!client && !server)
    {
        errx (1, "client or server must be selected");
    }

    if (client && server)
    {
        errx (1, "client/server mode is mutually exclusive");
    }

    if (!account)
    {
        errx (1, "No account specified");
    }

    if (!recipient)
    {
        errx (1, "No recipient specified");
    }

    if (!hostname)
    {
        errx (1, "No host specified");
    }

    if (port == 0)
    {
        errx (1, "No port specified");
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        err (1, "socket");
    }

    flag = 1;
    rv = setsockopt (s, IPPROTO_TCP, TCP_NODELAY, (void *)&flag, sizeof (int));
    if (rv < 0)
    {
        err (1, "setsockopt(TCP_NODELAY)");
    }

    host = gethostbyname (hostname);
    if (!host)
    {
        err (1, "gethostbyname");
    }

    bzero (&addr, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons (port);

    if (client)
    {
        memcpy (&addr.sin_addr.s_addr, host->h_addr, host->h_length);
        rv = connect (s, (struct sockaddr *)&addr, sizeof (addr));
        if (rv < 0)
        {
            err (1, "connect");
        }
        sock = s;
    } else if (server)
    {
        addr.sin_addr.s_addr = INADDR_ANY;
        rv = bind (s, (struct sockaddr *)&addr, sizeof (addr));
        if (rv < 0)
        {
            err (1, "bind");
        }
        listen (s, 5);

        sock = accept (s, (struct sockaddr *)&addr, &socklen);
        if (sock < 0)
        {
            err (1, "accept");
        }
        LOG ("Connection accepted");

    }

    LOG ("started");

    OTRL_INIT;
    us = otrl_userstate_create();

    otrl_privkey_read (us, "otr.private_key");

    result = otrl_instag_read (us, "inst.txt");
    HANDLE_GCRY_ERROR (result, "Local public key", 1);
  
    // Setup network reader thread
    rv = pthread_create (&cr, NULL, &network_reader, NULL);
    if (rv < 0)
    {
        err (1, "creating reader thread");
    }

    // UI loop
    for (;;)
    {
        line = readline ("libotr> ");
        if (!line)
        {
            errx (0, "DONE");
        }

        if (strcmp (line, "QUIT") == 0)
        {
            errx (0, "Termination requested");
        } else if (strcmp (line, "OTR") == 0)
        {
            // Query
            LOG ("Sending OTR query");
            write (sock, "\0\x08?OTRv3?", 12);
        } else
        {
            // Message
            result = otrl_message_sending
                (us,
                 &ops,
                 NULL,
	             account,                   // accountname
                 "local",                   // protocol
                 recipient,                 // recipient
                 OTRL_INSTAG_BEST,          // instag
                 line,                      // original_msg
                 NULL,                      // tlvs
                 &new_message,              // messagep
	             OTRL_FRAGMENT_SEND_ALL,    // fragPolicy
                 NULL,                      // context
                 NULL,                      // add_appdata
                 NULL);                     // data
            
            if (result != 0)
            {
                LOG ("Error sending message: %d", result);
            }
        }
    }
}
