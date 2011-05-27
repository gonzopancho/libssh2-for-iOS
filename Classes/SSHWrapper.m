//
//  SSHWrapper.m
//  libssh2-for-iOS
//
//  Created by Felix Schulze on 01.02.11.
//  Copyright 2010 Felix Schulze. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
//  @see: http://www.libssh2.org/examples/ssh2_exec.html

#import "SSHWrapper.h"

#include "libssh2.h"
#include "libssh2_config.h"
#include "libssh2_sftp.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

int sock;
LIBSSH2_SESSION *session;
LIBSSH2_CHANNEL *channel;
const char *keyfile1="id_rsa.pub"; // not working, yet
const char *keyfile2="id_rsa"; // not working, yet

int rc;

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;
	
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
	
    FD_ZERO(&fd);
	
    FD_SET(socket_fd, &fd);
	
    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);
	
    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;
	
    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;
	
    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
	
    return rc;
}

char *passwordFunc(const char *s)
{
    static char *pw = NULL;
    if (strlen(s)) {
        pw = s;
    } 
    return pw;
}

void keyboard_interactive(const char *name, int name_len, const char *instr, int instr_len, 
                          int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts, LIBSSH2_USERAUTH_KBDINT_RESPONSE *res, 
                          void **abstract)
{
    res[0].text = strdup(passwordFunc(""));
    res[0].length = strlen(passwordFunc(""));
}

@implementation SSHWrapper

-(int) connectToHost:(NSString *)host port:(int)port user:(NSString *)user password:(NSString *)password {
	const char* hostChar = [host cStringUsingEncoding:NSUTF8StringEncoding];
	const char* userChar = [user cStringUsingEncoding:NSUTF8StringEncoding];
	const char* passwordChar = [password cStringUsingEncoding:NSUTF8StringEncoding];
    char *userAuthList;
    const char *cause = NULL;
    const char *fingerprint;
    int i, error, auth_pw = 0;
    struct addrinfo hints, *res, *res0;

    (void) passwordFunc(passwordChar); /* save for future use */
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(hostChar, "ssh", &hints, &res0);
    if (error) {
        fprintf(stderr, "%s", gai_strerror(error));
        return 1;
        /*NOTREACHED*/
    }
    sock = -1;
    for (res = res0; res; res = res->ai_next) {
        sock = socket(res->ai_family, res->ai_socktype,
                   res->ai_protocol);
        if (sock < 0) {
            cause = "socket";
            continue;
        }
        
        if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
            cause = "connect";
            close(sock);
            sock = -1;
            continue;
        }
        
        break;  /* okay we got one */
    }
    if (sock < 0) {
        fprintf(stderr, "%s", cause);
        return 1;
        /*NOTREACHED*/
    }
    freeaddrinfo(res0);
    
    /* Create a session instance */
    session = libssh2_session_init();
    if (!session)
        return -1;
    
    // libssh2_trace(session, LIBSSH2_TRACE_AUTH|LIBSSH2_TRACE_ERROR);
   
    /* tell libssh2 we want it all done non-blocking */
    libssh2_session_set_blocking(session, 0);
	
    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    while ((rc = libssh2_session_startup(session, sock)) == LIBSSH2_ERROR_EAGAIN)
        ;
    if (rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        return -1;
    }
    
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
    
    // XXX track this, display in an alert if we've not seen it before
    printf("Fingerprint: ");
    for(i = 0; i < 16; i++) {
        printf("%02X:", (unsigned char)fingerprint[i]);
    }
    printf("\n");
    
    libssh2_session_set_blocking(session, 1);
    userAuthList = libssh2_userauth_list(session, userChar, strlen(userChar)); 
    
    if (strstr(userAuthList, "password") != NULL) {
        auth_pw |= 1;
    }
    if (strstr(userAuthList, "keyboard-interactive") != NULL) {
        auth_pw |= 2;
    }
    if (strstr(userAuthList, "publickey") != NULL) {
        auth_pw |= 4;
    }

    if (auth_pw & 1) {
        /* We can authenticate via password */
        if (libssh2_userauth_password(session, userChar, passwordChar)) {
            printf("\tAuthentication by password failed!\n");
            return 1;
        } else {
            printf("\tAuthentication by password succeeded.\n");
        }
    } else if (auth_pw & 2) {
        /* Or via keyboard-interactive */
        if (libssh2_userauth_keyboard_interactive(session, userChar, &keyboard_interactive) ) {
            printf("\tAuthentication by keyboard-interactive failed!\n");
            return 1;
        } else {
            printf("\tAuthentication by keyboard-interactive succeeded.\n");
        }
    } else if (auth_pw & 4) {
        /* Or by public key */
        if (libssh2_userauth_publickey_fromfile(session, userChar, keyfile1, keyfile2, passwordChar)) {
            printf("\tAuthentication by public key failed!\n");
            return 1;
        } else {
            printf("\tAuthentication by public key succeeded.\n");
        }
    } else {
        printf("No supported authentication methods found!\n");
        return 1;
    }


    libssh2_session_set_blocking(session, 0);    
	return 0;
}

-(NSString *)executeCommand:(NSString *)command {
	const char* commandChar = [command cStringUsingEncoding:NSUTF8StringEncoding];

	NSString *result;
	
    /* Exec non-blocking on the remove host */
    while( (channel = libssh2_channel_open_session(session)) == NULL &&
		  libssh2_session_last_error(session,NULL,NULL,0) == LIBSSH2_ERROR_EAGAIN )
    {
        waitsocket(sock, session);
    }
    if( channel == NULL )
    {
        fprintf(stderr,"Error\n");
        exit( 1 );
    }
    while( (rc = libssh2_channel_exec(channel, commandChar)) == LIBSSH2_ERROR_EAGAIN )
    {
        waitsocket(sock, session);
    }
    if( rc != 0 )
    {
        fprintf(stderr,"Error\n");
        exit( 1 );
    }
    for( ;; )
    {
        /* loop until we block */
        int rc1;
        do
        {
            char buffer[0x2000];
            rc1 = libssh2_channel_read( channel, buffer, sizeof(buffer) );
            if( rc1 > 0 )
            {
				result = [NSString stringWithCString:buffer encoding:NSASCIIStringEncoding];
            }
        }
        while( rc1 > 0 );
		
        /* this is due to blocking that would occur otherwise so we loop on
		 this condition */
        if( rc1 == LIBSSH2_ERROR_EAGAIN )
        {
            waitsocket(sock, session);
        }
        else
            break;
    }
    while( (rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN )
        waitsocket(sock, session);
	
    libssh2_channel_free(channel);
    channel = NULL;
	
    return result;
	
}


-(int) closeConnection {	
    libssh2_session_disconnect(session,"Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);
	
    close(sock);

    fprintf(stderr, "Connection closed\n");
	
	return 0;
}

@end
