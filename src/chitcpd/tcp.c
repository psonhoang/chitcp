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
    chilog(DEBUG, "[SEND] TOTAL BYTE IN SEND BUFFER IS %d", totalBytesRead);
    if (totalBytesRead == 0) 
    {
        return;
    }
    int possible_send_bytes = tcp_data->SND_WND - (tcp_data->SND_NXT - tcp_data->SND_UNA);
    chilog(DEBUG, "[SEND] TOTAL SEND WINDOW IS %d", possible_send_bytes);
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
    chilog(DEBUG, "[SEND] TOTAL BYTE GOING TO BE SENT IS %d", total_send_bytes);
    int payload_len;
    while (total_send_bytes > 0)
    {
        chilog(DEBUG, "[SEND] ENTER LOOP");
        /* Initialize send packet */
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        /* Send SND_WND bytes starting from SND_NXT */
        if (total_send_bytes >= TCP_MSS)
        {
            payload_len = TCP_MSS;
        }
        else
        {
            payload_len = total_send_bytes + TCP_HEADER_NOOPTIONS_SIZE;
        }
        payload_len = TCP_MSS;
        chilog(DEBUG, "[SEND] TOTAL PAYLOAD LEN IS %d", payload_len);
        uint8_t payload[payload_len];
        bytesRead = circular_buffer_read(&send_buf, payload, payload_len, FALSE);
        chilog(DEBUG, "[SEND] TOTAL BYTES READ FROM SENT BUFFER IS %d", bytesRead);
        //chilog(DEBUG, "[SEND] SENT DATA IS %s", bytesRead);
        chilog(DEBUG, "DATA REMAINING IN BUFFER IS %d", circular_buffer_count(&send_buf));
        if (bytesRead > 0) {
            total_send_bytes -= bytesRead;
            chilog(DEBUG, "[SEND] TOTAL BYTES GOING TO BE SENT 2 IS %d", total_send_bytes);
            /* Create send packet */
            chitcpd_tcp_packet_create(entry, send_packet, payload, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
            /* Update TCP variables and send header */
            // update payload
            tcp_data->SND_NXT = tcp_data->SND_NXT + bytesRead;
            send_header->ack = 1;
            send_header->ack_seq = tcp_data->RCV_NXT;
            send_header->seq = tcp_data->SND_NXT;
            send_header->win = tcp_data->RCV_WND;
            /* Send packet */
            chitcpd_send_tcp_packet(si, entry, send_packet);
        }
    }
}

int chitcpd_tcp_handle_PACKET_ARRIVAL(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_state_t tcp_state = entry->tcp_state;
    //chilog(DEBUG, "[LISTEN] IT COMES TO THE PACKET_ARRIVAL HANDLER FUNCTION");
    //chilog(DEBUG,"event is %d", event);
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
    if (tcp_state == CLOSED)
    {
        // do nothing
        return 0;
    }
    else if (tcp_state == LISTEN)
    {
        //chilog(DEBUG,"[LISTEN] IT COMES INSIDE LISTEN EVENT THE PACKET_ARRIVAL HANDLER FUNCTION");
        if (header->ack == 1)
        {
            // do nothing
            //return 0;
        }
        if (header->syn == 1)
        {
            uint32_t ISS = 500;
            tcp_data->ISS = ISS;
            tcp_data->SND_UNA = ISS;
            tcp_data->SND_NXT = ISS + 1;
            tcp_data->RCV_NXT = header->seq + 1;
            tcp_data->RCV_WND = circular_buffer_capacity(&tcp_data->recv);
            tcp_data->IRS = header->seq;
            //chilog(DEBUG,"LISTEN receives sequence to be is %d", header->seq);
            circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS + 1);
            circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->ISS + 1);
            //
            send_header->syn = 1;
            send_header->ack = 1;
            send_header->seq = ISS;
            send_header->ack_seq = header->seq + 1;
            send_header->win = tcp_data->RCV_WND;
            chitcpd_send_tcp_packet(si, entry, send_packet);
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            return 0;
        }
    }
    else if (tcp_state == SYN_SENT)
    {
        //chilog(DEBUG,"[LISTEN] IT COMES INSIDE SYN_SENT EVENT THE PACKET_ARRIVAL HANDLER FUNCTION");
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
            tcp_data->SND_UNA = header->ack_seq;
            tcp_data->SND_NXT = header->ack_seq;
            //chilog(DEBUG,"[LISTEN] SYN_SENT receives ack sequence to be is %d", header->ack_seq);
            
            tcp_data->RCV_NXT = header->seq + 1;
            tcp_data->IRS = header->seq;
            tcp_data->SND_WND = header->win;
            circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS + 1);
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
                chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            }
            return 0;
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
        //chilog(DEBUG,"[LISTEN] IT COMES TO ELSE IN THE PACKET_ARRIVAL HANDLER FUNCTION");
        uint16_t SEG_LEN = SEG_LEN(packet);
        uint16_t RCV_WND = tcp_data->RCV_WND;
        if ((RCV_WND == 0) && (SEG_LEN == 0))
        {
            //chilog(DEBUG,"[LISTEN] IT COMES TO FIRST ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            if (header->seq != tcp_data->RCV_NXT)
            {
                chilog(DEBUG,"[LISTEN] IT DOESN'T PASS FIRST ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
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
                if (tcp_data->RCV_NXT > header->seq)
                {
                    chilog(DEBUG, "[LISTEN] RCV_NXT: %d", tcp_data->RCV_NXT);
                    chilog(DEBUG, "[LISTEN] header->seq: %d", header->seq);
                    chilog(DEBUG,"[LISTEN] rcv_nxt > sequence number in SECOND ACCEPTABILITY TEST");
                }
                if (header->seq > (tcp_data->RCV_NXT + tcp_data->RCV_WND))
                {
                    chilog(DEBUG,"[LISTEN] sequence num > receive fram in SECOND ACCEPTABILITY TEST");
                }
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
            chilog(DEBUG,"[LISTEN] IT COMES TO THIRD ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            send_header->ack = 1;
            send_header->seq = tcp_data->SND_NXT;
            send_header->ack_seq = tcp_data->RCV_NXT;
            send_header->win = tcp_data->RCV_WND;
            chitcpd_send_tcp_packet(si, entry, send_packet);
            return 0;
        }
        else if ((RCV_WND > 0) && (SEG_LEN > 0))
        {
            chilog(DEBUG,"[LISTEN] IT COMES TO FOURTH ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            if (!(((tcp_data->RCV_NXT <= header->seq) &&
                (header->seq < (tcp_data->RCV_NXT + tcp_data->RCV_WND))) ||
                ((tcp_data->RCV_NXT <= (header->seq + SEG_LEN - 1)) &&
                ((header->seq + SEG_LEN - 1) < (tcp_data->RCV_NXT + tcp_data->RCV_WND)))))
            {
                // if (tcp_data->RCV_NXT > header->seq)
                // {
                //     chilog(DEBUG,"[LISTEN] rcv_nxt > sequence number in FOURTH ACCEPTABILITY TEST");
                //     chilog(DEBUG,"rcv_next is %d", tcp_data->RCV_NXT);
                //     chilog(DEBUG,"sequence_num is %d", header->seq);
                //     chilog(DEBUG,"IRS is %d", tcp_data->IRS);
                    
                // }
                chilog(DEBUG,"[LISTEN] IT DOESN'T PASS FOURTH ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
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
            chilog(DEBUG,"[LISTEN] IT COMES TO HEADER SYN == 1 TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
                // error
            return 0;
        }
        if (header->ack == 0)
        {
                // error
                chilog(DEBUG,"WHEN ACK == 0 IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            return 0;
        }
        else
        {
            chilog(DEBUG,"[LISTEN] IT COMES TO ACK == 1 IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            if (tcp_state == SYN_RCVD)
            {
                chilog(DEBUG,"[LISTEN] IT COMES INSIDE SYN_RCVD EVENT THE PACKET_ARRIVAL HANDLER FUNCTION");
                chilog(DEBUG, "[LISTEN] header->ack = %d", header->ack);
                chilog(DEBUG, "[LISTEN] tcp_data->ISS = %d", tcp_data->ISS);
                chilog(DEBUG, "[LISTEN] tcp_data->SND_UNA = %d", tcp_data->SND_UNA);
                chilog(DEBUG, "[LISTEN] tcp_data->SND_NEXT = %d", tcp_data->SND_NXT);
                if ((tcp_data->SND_UNA <= header->ack_seq) &&
                    (header->ack_seq <= tcp_data->SND_NXT))
                {
                    tcp_data->SND_UNA = header->ack_seq;
                    tcp_data->SND_NXT = header->ack_seq;
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                    return 0;
                }
            }
            else
            {
                chilog(DEBUG,"[LISTEN] IT COMES OTHER EVENTS IN THE PACKET_ARRIVAL HANDLER FUNCTION");
                if ((tcp_data->SND_UNA <= header->ack_seq) &&
                    (header->ack_seq <= tcp_data->SND_NXT))
                {
                    tcp_data->SND_UNA = header->ack_seq;
                    tcp_data->SND_WND = header->win;
                    chitcpd_process_send_buffer(si, entry);
                }
                else if (header->ack_seq > tcp_data->SND_NXT)
                {
                    chilog(DEBUG, "[LISTEN] header->ack_seq: %d", header->ack_seq);
                    chilog(DEBUG, "[LISTEN] tcp_data->SND_NXT: %d", tcp_data->SND_NXT);
                    chilog(DEBUG, "[LISTEN] header->ack_seq > tcp_data->SND_NXT");
                    send_header->ack = 1;
                    send_header->seq = tcp_data->SND_NXT;
                    send_header->ack_seq = tcp_data->RCV_NXT;
                    send_header->win = tcp_data->RCV_WND;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                }
                else 
                {
                    //ignore
                    return 0;
                }
                if (tcp_state == FIN_WAIT_1)
                {
                    if (header->fin != 1)
                    {
                        //tcp_data->SND_UNA += 1;
                        chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
                        return 0;
                    }
                }
                else if (tcp_state == FIN_WAIT_2)
                {
                }
                else if (tcp_state == CLOSING)
                {
                    chilog(DEBUG, "[CLOSING] Transitioning to CLOSED state");
                    chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                    return 0;
                }
                else if (tcp_state == LAST_ACK)
                {
                    chilog(DEBUG, "[LAST_ACK] Transitioning to CLOSED state");

                    chitcpd_update_tcp_state(si, entry, CLOSED);
                    return 0;
                }
            }
            // seventh step: process segment
            if ((tcp_state == ESTABLISHED) || 
                (tcp_state == FIN_WAIT_1) || 
                (tcp_state == FIN_WAIT_2))
            {
                /* Copy to recv buffer and updates RCV_NXT */
                if ((header->fin != 1) && (tcp_state == ESTABLISHED))
                {
                    int bytesWritten = circular_buffer_write(&tcp_data->recv, TCP_PAYLOAD_START(packet), TCP_PAYLOAD_LEN(packet), FALSE);
                    tcp_data->RCV_NXT += bytesWritten;
                    tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
                    send_header->ack = 1;
                    send_header->seq = tcp_data->SND_NXT;
                    send_header->ack_seq = tcp_data->RCV_NXT;
                    send_header->win = tcp_data->RCV_WND;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                }
                /* Send ACK */
            }
            else 
            {
                return 0;
            }
                // eighth step: Tam
            if ((tcp_state == CLOSED) || (tcp_state == LISTEN) || (tcp_state == SYN_SENT))
            {
                return 0;
            }
            else
            {
                if (header->fin == 1)
                {
                    /* Send ACK */
                    tcp_data->RCV_NXT = header->seq + 1; // = 2
                    send_header->ack = 1;
                    send_header->seq = tcp_data->SND_NXT;
                    send_header->ack_seq = tcp_data->RCV_NXT;
                    send_header->win = tcp_data->RCV_WND;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    /* Transitions to next states in connection termination */
                    if ((tcp_state == SYN_RCVD) || (tcp_state == ESTABLISHED))
                    {
                        if (tcp_state == ESTABLISHED) {
                            chilog(DEBUG, "[ESTABLISHED] moving into CLOSE_WAIT state");
                        }
                        chitcpd_update_tcp_state(si, entry, CLOSE_WAIT);
                        return 0;
                    }
                    else if (tcp_state == FIN_WAIT_1)
                    {
                        /* Transitions to FIN_WAIT_2 */
                        chilog(DEBUG, "[FIN_WAIT_1] Transititiong to CLOSING");
                        chitcpd_update_tcp_state(si, entry, CLOSING);
                        return 0;
                    }
                    else if (tcp_state == FIN_WAIT_2)
                    {
                        /* Transitions to TIME_WAIT */
                        chilog(DEBUG, "[FIN_WAIT_2] Transitioning to TIME_WAIT");
                        chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                        chitcpd_update_tcp_state(si, entry, CLOSED);
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
        chilog(DEBUG, "[CLOSED] APPLICATION_CONNECT");
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

        uint32_t ISS = 0;
        tcp_data->ISS = ISS;
        tcp_data->SND_UNA = ISS;
        tcp_data->SND_NXT = ISS + 1;
        tcp_data->RCV_WND = circular_buffer_capacity(&tcp_data->recv);
        circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->ISS + 1);
        tcp_packet_t *packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, packet, NULL, 0);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        header->syn = 1;
        header->seq = ISS;
        chilog(DEBUG,"ISS_A is %d", ISS);
        header->ack_seq = 0;
        header->win = tcp_data->RCV_WND;
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
        chilog(DEBUG, "[LISTEN] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
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
        chilog(DEBUG, "[SYNC_RCVD] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
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
        chilog(DEBUG, "[ESTABLISHED] APPLICATION_CLOSE");
        /* Mark the socket is closing */
        tcp_data->closing = true;
        /* Clear send buffer */
        // while (circular_buffer_count(&tcp_data->send) != 0)
        // {
        //     chilog(DEBUG, "[ESTABLISHED] APPLICATION_CLOSE - stuck in send loop!");
        //     // tcp_data is updated during these sends
        //     chitcpd_process_send_buffer(si, entry);
        // }
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        send_header->fin = 1;
        send_header->ack = 1;
        send_header->seq = tcp_data->SND_NXT;
        send_header->ack_seq = tcp_data->RCV_NXT;
        send_header->win = tcp_data->RCV_WND;
        chitcpd_send_tcp_packet(si, entry, send_packet);
        tcp_data->SND_NXT += 1;
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
        chilog(DEBUG, "[FIN_WAIT_1] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
        chilog(DEBUG, "[FIN_WAIT_1] APPLICATION_RECEIVE");
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
        chilog(DEBUG, "[FIN_WAIT_2] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
        chilog(DEBUG, "[FIN_WAIT_2] APPLICATION_RECEIVE");
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
        chilog(DEBUG, "[CLOSE_WAIT] APPLICATION_CLOSE");
        // while (circular_buffer_count(&tcp_data->send) != 0)
        // {
        //     chilog(DEBUG, "[CLOSE_WAIT] stuck in send buffer loop!");
        //     chitcpd_process_send_buffer(si, entry);
        // }
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
        tcp_data->SND_NXT += 1;
        chitcpd_update_tcp_state(si, entry, LAST_ACK);
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chilog(DEBUG, "[CLOSE_WAIT] PACKET_ARRIVAL");
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
        chilog(DEBUG, "[CLOSING] PACKET_ARRIVAL");
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
        chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    //chilog(DEBUG, "[TIME_WAIT] Immediately moving into CLOSED state");
    //chitcpd_update_tcp_state(si, entry, CLOSED);
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
        chilog(DEBUG, "[LAST_ACK] PACKET_ARRIVAL");
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
