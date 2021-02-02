/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>




void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    /* Cleanup of additional tcp_data_t fields goes here */
}

// P2a
int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CONNECT)
    {
        /* Your code goes here */
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

        uint32_t ISS = rand();
        tcp_data->ISS = ISS;
        tcp_data->SND_UNA = ISS;
        tcp_data->SND_NXT = ISS + 1;
        tcp_packet_t *packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, packet, NULL, 0);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        header->syn = 1;
        header->seq = ISS;
        header->ack_seq = 0;
        // header->win
        chitcpd_send_tcp_packet(si, entry, packet);
        chitcpd_update_tcp_state(si, entry, SYN_SENT);

    }
    else if (event == CLEANUP)
    {
        /* Any additional cleanup goes here */
    }
    else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_packet_t *packet = NULL;
        if (tcp_data->pending_packets) {
        /* tcp_data->pending_packets points to the head node of the list */
            packet = tcp_data->pending_packets->packet;

            /* This removes the list node at the head of the list */
            chitcp_packet_list_pop_head(&tcp_data->pending_packets);
        }
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        if (header->syn == 1) 
        {
            // if SYN message
            // send back SYN message cua host and ACK
            tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
            chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
            uint32_t ISS = rand();
            tcp_data->ISS = ISS;
            tcp_data->SND_UNA = ISS;
            tcp_data->SND_NXT = ISS + 1;
            tcp_data->RCV_NXT = header->seq + 1;
            //
            send_header->syn = 1;
            send_header->ack = 1;
            send_header->seq = ISS;
            send_header->ack_seq = header->seq + 1;
            // send_header->win
            chitcpd_send_tcp_packet(si, entry, send_packet);
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
        }
    }
    else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        // if ACK
        // ESTABLISHED
        // done
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_packet_t *packet = NULL;
        if (tcp_data->pending_packets) {
        /* tcp_data->pending_packets points to the head node of the list */
            packet = tcp_data->pending_packets->packet;

            /* This removes the list node at the head of the list */
            chitcp_packet_list_pop_head(&tcp_data->pending_packets);
        }
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        if (header->ack == 1)
        {
            tcp_data->SND_UNA = header->ack;
            chitcpd_update_tcp_state(si, entry, ESTABLISHED);
        }  
    }
    else if (event == TIMEOUT_RTX)
    {
    /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        // if SYN message
        // transition to ESTABLISHED
        // SEND back ACK
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_packet_t *packet = NULL;
        if (tcp_data->pending_packets) {
        /* tcp_data->pending_packets points to the head node of the list */
            packet = tcp_data->pending_packets->packet;

            /* This removes the list node at the head of the list */
            chitcp_packet_list_pop_head(&tcp_data->pending_packets);
        }
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        if ((header->syn == 1) && (header->ack == 1))
        {
            // if SYN message
            // send back ACK
            tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
            chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
            tcp_data->SND_UNA = header->ack;
            tcp_data->SND_NXT = header->ack;
            tcp_data->RCV_NXT = header->seq + 1;
            //
            send_header->ack = 1;
            send_header->seq = header->ack;
            send_header->ack_seq = header->seq + 1;
            // send_header->win
            chitcpd_send_tcp_packet(si, entry, send_packet);
            chitcpd_update_tcp_state(si, entry, ESTABLISHED);
        }       
    }
    else if (event == TIMEOUT_RTX)
    {
    /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_SEND)
    {
        /* Your code goes here */
        // check if send buffer is empty
        // if not send data (check send window)
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        // CASE: FIN
        // check if seq number is valid to put into receive buffer
        // check if message is FIN
        // send ACK // CHECK
        // transition to CLOSE_WAIT
        // call application receive  
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
        // update sliding window
    }
    else if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
        // send FIN seq to host B
        // transition to FIN_WAIT1
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        // If receive ACK
        // transition to FIN_WAIT2

        // If receive FIN
        // send ACK
        // transition to CLOSING
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */

    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
       chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        // if receive FIN from other host
        // Send ACK
        // transition to TIME_WAIT
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
        // send FIN to other host
        // transition to LAST_ACK
        // Queue this request until all preceding SENDs have been
        // segmentized; then send a FIN segment, enter CLOSING state.
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

        uint32_t ISS = rand();
        tcp_data->ISS = ISS;
        tcp_data->SND_UNA = ISS;
        tcp_data->SND_NXT = ISS + 1;
        tcp_packet_t *packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, packet, NULL, 0);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        header->syn = 1;
        header->seq = rand();
        header->ack_seq = 0;
        // header->win
        chitcpd_send_tcp_packet(si, entry, packet);
        chitcpd_update_tcp_state(si, entry, SYN_SENT);
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
       chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);


    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        // if receive ACK
        // Transition to Time wait
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
       chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    chitcpd_update_tcp_state(si, entry, CLOSED);
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen.");

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        // if receive ACK 
        // CLOSE
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
       chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */
