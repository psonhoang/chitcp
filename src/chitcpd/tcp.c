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

/* P2a */

void chitcpd_process_send_buffer(serverinfo_t *si, chisocketentry_t *entry)
{
    /* Empties send buffer */
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    circular_buffer_t send_buf = tcp_data->send;
    /* Segmentizes send buffer based on send window */
    int totalBytesRead = circular_buffer_count(&send_buf);
    if (totalBytesRead == 0) 
    {
        return;
    }
    int possible_send_bytes = tcp_data->SND_WND - (tcp_data->SND_NXT - tcp_data->SND_UNA);
    int total_send_bytes = 0;
    int bytesRead;
    if (possible_send_bytes >= totalBytesRead)
    {
        total_send_bytes = totalBytesRead;
    }
    else
    {
        total_send_bytes = possible_send_bytes;
    }
    int payload_len;
    while (total_send_bytes > 0)
    {
        /* Initialize send packet */
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        /* Send SND_WND bytes starting from SND_NXT */
        if (total_send_bytes >= TCP_MSS)
        {
            payload_len = TCP_MSS;
        }
        else
        {
            payload_len = total_send_bytes;
        }
        uint8_t payload[payload_len];
        bytesRead = circular_buffer_read(&send_buf, payload, payload_len, FALSE);
        if (bytesRead > 0) {
            total_send_bytes -= bytesRead;
            /* Create send packet */
            chitcpd_tcp_packet_create(entry, send_packet, payload, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
            /* Update TCP variables and send header */
            // update payload
            tcp_data->SND_NXT = tcp_data->SND_NXT + bytesRead;
            send_header->ack = 1;
            send_header->ack_seq = tcp_data->RCV_NXT;
            send_header->seq = tcp_data->SND_NXT;
            send_header->win = circular_buffer_capacity(&tcp_data->recv);
            /* Send packet */
            chitcpd_send_tcp_packet(si, entry, send_packet);
        }
    }
}

int chitcpd_tcp_handle_PACKET_ARRIVAL(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *packet = NULL;
    if (tcp_data->pending_packets)
    {
        /* tcp_data->pending_packets points to the head node of the list */
        packet = tcp_data->pending_packets->packet;

        /* This removes the list node at the head of the list */
        chitcp_packet_list_pop_head(&tcp_data->pending_packets);
    }
    tcphdr_t *header = TCP_PACKET_HEADER(packet);
    tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
    chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
    tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
    if (event == CLOSED)
    {
        // do nothing
        return 0;
    }
    else if (event == LISTEN)
    {
        if (header->ack == 1)
        {
            // do nothing
            //return 0;
        }
        if (header->syn == 1)
        {
            uint32_t ISS = rand();
            tcp_data->ISS = ISS;
            tcp_data->SND_UNA = ISS;
            tcp_data->SND_NXT = ISS + 1;
            tcp_data->RCV_NXT = header->seq + 1;
            tcp_data->IRS = header->seq;
            circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS + 1);
            //
            send_header->syn = 1;
            send_header->ack = 1;
            send_header->seq = ISS;
            send_header->ack_seq = header->seq + 1;
            send_header->win = circular_buffer_capacity(&tcp_data->recv);
            chitcpd_send_tcp_packet(si, entry, send_packet);
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            //return 0;
        }
    }
    else if (event == SYN_SENT)
    {
        if ((header->syn == 1) && (header->ack == 1))
        {
            // if SYN message
            // send back ACK
            // if (!((tcp_data->SND_UNA <= header->ack_seq) &&
            //     (header->ack_seq <= tcp_data->SND_NXT)))
            // {
            //     // not acceptable
            //     return 0;
            // }
            tcp_data->SND_UNA = header->ack;
            tcp_data->SND_NXT = header->ack;
            tcp_data->RCV_NXT = header->seq + 1;
            tcp_data->IRS = header->seq;
            tcp_data->SND_WND = header->win;
            //
            if (tcp_data->SND_UNA > tcp_data->ISS)
            {
                send_header->ack = 1;
                send_header->seq = tcp_data->SND_NXT;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
            }
            else
            {
                send_header->ack = 1;
                send_header->syn = 1;
                send_header->seq = tcp_data->ISS;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
            }
            //return 0;
        }
    }
    else
    {
        // SYN-RECEIVED STATE
        // ESTABLISHED STATE
        // FIN-WAIT-1 STATE
        // FIN-WAIT-2 STATE
        // CLOSE-WAIT STATE
        // CLOSING STATE
        // LAST-ACK STATE
        // TIME-WAIT STATE

        // check acceptability
        // * TO DO for Tam: Acceptability
        uint16_t SEG_LEN = SEG_LEN(packet);
        uint16_t RCV_WND = tcp_data->RCV_WND;
        if ((RCV_WND == 0) && (SEG_LEN == 0))
        {
            if (header->seq != tcp_data->RCV_NXT)
            {
                send_header->ack = 1;
                send_header->seq = tcp_data->SND_NXT;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                return 0;
            }
        }
        else if ((RCV_WND > 0) && (SEG_LEN == 0))
        {
            if (!((tcp_data->RCV_NXT <= header->seq) &&
                  (header->seq < (tcp_data->RCV_NXT + tcp_data->RCV_WND))))
            {

                send_header->ack = 1;
                send_header->seq = tcp_data->SND_NXT;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                return 0;
            }
        }
        else if ((RCV_WND == 0) && (SEG_LEN > 0))
        {
            send_header->ack = 1;
            send_header->seq = tcp_data->SND_NXT;
            send_header->ack_seq = tcp_data->RCV_NXT;
            send_header->win = tcp_data->RCV_WND;
            chitcpd_send_tcp_packet(si, entry, send_packet);
            return 0;
        }
        else if ((RCV_WND > 0) && (SEG_LEN > 0))
        {
            if (!(((tcp_data->RCV_NXT <= header->seq) &&
                   (header->seq < (tcp_data->RCV_NXT + tcp_data->RCV_WND))) ||
                  ((tcp_data->RCV_NXT <= (header->seq + SEG_LEN - 1)) &&
                   ((header->seq + SEG_LEN - 1) < (tcp_data->RCV_NXT + tcp_data->RCV_WND)))))
            {
                send_header->ack = 1;
                send_header->seq = tcp_data->SND_NXT;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                return 0;
            }
        }
        if (header->syn == 1)
        {
                // error
            return 0;
        }
        if (header->ack == 0)
        {
                // error
            return 0;
        }
        else
        {
            if (event == SYN_RCVD)
            {
                if ((tcp_data->SND_UNA <= header->ack_seq) &&
                    (header->ack_seq <= tcp_data->SND_NXT))
                {
                    tcp_data->SND_UNA = header->ack;
                    tcp_data->SND_NXT = header->ack;
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                    //return 0;
                }
            }
            else
            {
                if ((tcp_data->SND_UNA <= header->ack_seq) &&
                    (header->ack_seq <= tcp_data->SND_NXT))
                {
                    tcp_data->SND_UNA = header->ack_seq;
                    tcp_data->SND_WND = header->win;
                }
                else if (header->ack_seq > tcp_data->SND_NXT)
                {
                    send_header->ack = 1;
                    send_header->seq = tcp_data->SND_NXT;
                    send_header->ack_seq = tcp_data->RCV_NXT;
                    send_header->win = tcp_data->RCV_WND;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    return 0;
                }
                else 
                {
                    //ignore
                    return 0;
                }
                if (event == FIN_WAIT_1)
                {
                    if (header->fin != 1)
                    {
                        chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
                        return 0;
                    }
                }
                else if (event == FIN_WAIT_2)
                {
                }
                else if (event == CLOSING)
                {
                    chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                    return 0;
                }
                else if (event == LAST_ACK)
                {
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                    return 0;
                }
            }
                // seventh step: process segment
            if (event == ESTABLISHED || 
                event == FIN_WAIT_1 || 
                event == FIN_WAIT_2)
            {
                /* Copy to recv buffer and updates RCV_NXT */
                int bytesWritten = circular_buffer_write(&tcp_data->recv, packet->raw, packet->length, true);
                tcp_data->RCV_NXT += bytesWritten;
                tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
                /* Send ACK */
                send_header->ack = 1;
                send_header->seq = tcp_data->SND_NXT;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
            }
                // eighth step: Tam
            if ((event == CLOSED) || (event == LISTEN) || (event == SYN_SENT))
            {
                return 0;
            }
            else
            {
                if (header->fin == 1)
                {
                    tcp_data->RCV_NXT = header->seq + 1;
                    send_header->ack = 1;
                    send_header->seq = tcp_data->SND_NXT;
                    send_header->ack_seq = tcp_data->RCV_NXT;
                    send_header->win = tcp_data->RCV_WND;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    if ((event == SYN_RCVD) || (event == ESTABLISHED))
                    {
                        chitcpd_update_tcp_state(si, entry, CLOSE_WAIT);
                        return 0;
                    }
                    else if (event == FIN_WAIT_1)
                    {
                        // need to check
                        chitcpd_update_tcp_state(si, entry, CLOSING);
                        return 0;
                    }
                    else if (event == FIN_WAIT_2)
                    {
                        chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                        return 0;
                    }
                }
            }
        }
    }
}

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
        circular_buffer_set_seq_initial(&tcp_data->send, ISS + 1);
        tcp_packet_t *packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, packet, NULL, 0);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        header->syn = 1;
        header->seq = ISS;
        header->ack_seq = 0;
        header->win = circular_buffer_capacity(&tcp_data->recv);
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
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
        // tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        // tcp_packet_t *packet = NULL;
        // if (tcp_data->pending_packets)
        // {
        //     /* tcp_data->pending_packets points to the head node of the list */
        //     packet = tcp_data->pending_packets->packet;

        //     /* This removes the list node at the head of the list */
        //     chitcp_packet_list_pop_head(&tcp_data->pending_packets);
        // }
        // tcphdr_t *header = TCP_PACKET_HEADER(packet);
        // if (header->syn == 1)
        // {
        //     // if SYN message
        //     // send back SYN message cua host and ACK
        //     tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        //     chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        //     tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        //     uint32_t ISS = rand();
        //     tcp_data->ISS = ISS;
        //     tcp_data->SND_UNA = ISS;
        //     tcp_data->SND_NXT = ISS + 1;
        //     tcp_data->RCV_NXT = SEG_SEQ(packet) + 1; // header->seq + 1
        //     tcp_data->IRS = SEG_SEQ(packet);         // header->seq
        //     //
        //     send_header->syn = 1;
        //     send_header->ack = 1;
        //     send_header->seq = ISS;
        //     send_header->ack_seq = SEG_SEQ(packet) + 1; // header->seq + 1
        //     send_header->win = circular_buffer_capacity(&tcp_data->recv);
        //     chitcpd_send_tcp_packet(si, entry, send_packet);
        //     chitcpd_update_tcp_state(si, entry, SYN_RCVD);
        // }
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
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
        // tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        // tcp_packet_t *packet = NULL;
        // if (tcp_data->pending_packets)
        // {
        //     /* tcp_data->pending_packets points to the head node of the list */
        //     packet = tcp_data->pending_packets->packet;

        //     /* This removes the list node at the head of the list */
        //     chitcp_packet_list_pop_head(&tcp_data->pending_packets);
        // }
        // tcphdr_t *header = TCP_PACKET_HEADER(packet);
        // if (header->ack == 1)
        // {
        //     if ((tcp_data->SND_UNA <= header->ack_seq) &&
        //         (header->ack_seq <= tcp_data->SND_NXT))
        //     {
        //         tcp_data->SND_UNA = header->ack;
        //         tcp_data->SND_NXT = header->ack;
        //         chitcpd_update_tcp_state(si, entry, ESTABLISHED);
        //     }
        // }
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
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
        // tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        // tcp_packet_t *packet = NULL;
        // if (tcp_data->pending_packets)
        // {
        //     /* tcp_data->pending_packets points to the head node of the list */
        //     packet = tcp_data->pending_packets->packet;

        //     /* This removes the list node at the head of the list */
        //     chitcp_packet_list_pop_head(&tcp_data->pending_packets);
        // }
        // tcphdr_t *header = TCP_PACKET_HEADER(packet);
        // if ((header->syn == 1) && (header->ack == 1))
        // {
        //     // if SYN message
        //     // send back ACK
        //     tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        //     chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        //     tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        //     tcp_data->SND_UNA = header->ack;
        //     tcp_data->SND_NXT = header->ack;
        //     tcp_data->RCV_NXT = header->seq + 1;
        //     tcp_data->IRS = header->seq;
        //     //
        //     send_header->ack = 1;
        //     send_header->seq = tcp_data->SND_NXT;
        //     send_header->ack_seq = tcp_data->RCV_NXT;
        //     // send_header->win
        //     send_header->win = tcp_data->RCV_WND;
        //     chitcpd_send_tcp_packet(si, entry, send_packet);
        //     chitcpd_update_tcp_state(si, entry, ESTABLISHED);
        // }
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
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_SEND)
    {
        /* Your code goes here */
        // check if send buffer is empty
        // if not send data (check send window)
        chitcpd_process_send_buffer(si, entry);
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
        // tcp_packet_t *packet = NULL;
        // if (tcp_data->pending_packets)
        // {
        //     /* tcp_data->pending_packets points to the head node of the list */
        //     packet = tcp_data->pending_packets->packet;

        //     /* This removes the list node at the head of the list */
        //     chitcp_packet_list_pop_head(&tcp_data->pending_packets);
        // }
        // tcphdr_t *header = TCP_PACKET_HEADER(packet);
        // // TODO FOR Hoang: process the segment text
        // if (header->fin == 1)
        // {

        //     // TODO :HOANG
        //     // CASE: FIN
        //     // send ACK // CHECK
        //     // pending RECEIVEs with same message
        //     // transition to CLOSE_WAIT
        //     // call application receive
        // }
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
        /* Update RCV_WND */
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    }
    else if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
        // TODO: Tam
        // transition to FIN_WAIT1, send FIN
        // Queue this until all preceding SENDs have been segmentized, then
        // form a FIN segment and send it. /* PROCESS BUFFER function */
        // Done
        while (circular_buffer_count(&tcp_data->send) != 0)
        {
            chitcpd_process_send_buffer(si, entry);
        }
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        send_header->fin = 1;
        send_header->ack = 1;
        send_header->seq = tcp_data->SND_NXT;
        send_header->ack_seq = tcp_data->RCV_NXT;
        send_header->win = tcp_data->RCV_WND;
        chitcpd_send_tcp_packet(si, entry, send_packet);
        chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
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
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == PACKET_ARRIVAL)
    {
        // TODO: Tam
        /* Your code goes here */
        // If receive ACK
        // transition to FIN_WAIT2
        //chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);

        // If receive FIN
        // send ACK
        // transition to CLOSING
        // DONE
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
        /* Update RCV_WND */
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
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
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        /* TODO: Tam */
        // if receive FIN from other host
        // Send ACK
        // transition to TIME_WAIT
        // DONE
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
        /* Update RCV_WND */
        tcp_data->RCV_WND = tcp_data->recv.maxsize - tcp_data->recv.count;
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
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
        /* TODO: Tam */
        // send FIN to other host
        // transition to LAST_ACK
        // Queue this request until all preceding SENDs have been
        // segmentized; then send a FIN segment, enter LAST_ACK state.
        // DONE
        while (circular_buffer_count(&tcp_data->send) != 0)
        {
            chitcpd_process_send_buffer(si, entry);
        }
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        send_header->fin = 1;
        send_header->ack = 1;
        send_header->seq = tcp_data->SND_NXT;
        send_header->ack_seq = tcp_data->RCV_NXT;
        send_header->win = tcp_data->RCV_WND;
        chitcpd_send_tcp_packet(si, entry, send_packet);
        chitcpd_update_tcp_state(si, entry, LAST_ACK);
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
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
        /* TODO :Tam */
        /* Your code goes here */
        // if receive ACK
        // Transition to Time wait
        // DONE
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
        /* TODO :Tam */
        /* Your code goes here */
        // if receive ACK
        // CLOSE
        // DONE
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
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
