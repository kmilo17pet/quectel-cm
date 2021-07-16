/******************************************************************************
  @file    atc.c
  @brief   at command.

  DESCRIPTION
  Connectivity Management Tool for USB network adapter of Quectel wireless cellular modules.

  INITIALIZATION AND SEQUENCING REQUIREMENTS
  None.

  ---------------------------------------------------------------------------
  Copyright (c) 2016 - 2020 Quectel Wireless Solution, Co., Ltd.  All Rights Reserved.
  Quectel Wireless Solution Proprietary and Confidential.
  ---------------------------------------------------------------------------
******************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <stddef.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <poll.h>
#include <sys/time.h>
#include <endian.h>
#include <time.h>
#include <sys/types.h>
#include <limits.h>
#include <inttypes.h>

extern int asprintf(char **s, const char *fmt, ...);

#include "QMIThread.h"

#include "atchannel.h"
#include "at_tok.h"

static int asr_style_atc = 0;
#define safe_free(__x) do { if (__x) { free((void *)__x); __x = NULL;}} while(0)
#define safe_at_response_free(__x) { if (__x) { at_response_free(__x); __x = NULL;}}

#define at_response_error(err, p_response) \
    (err \
    || p_response == NULL \
    || p_response->finalResponse == NULL \
    || p_response->success == 0)

static int atc_init(PROFILE_T *profile) {
    int err;
    ATResponse *p_response = NULL;

    (void)profile;

    err = at_handshake();
    if (err) {
        dbg_time("handshake fail, TODO ... ");
        goto exit;
    }

    at_send_command("AT+QCFG=\"NAT\",1", NULL);
    at_send_command_singleline("AT+QCFG=\"usbnet\"", "+QCFG:", NULL);
    at_send_command_multiline("AT+QNETDEVCTL=?", "+QNETDEVCTL:", NULL);
    at_send_command("AT+CGREG=2", NULL);

    err = at_send_command_singleline("AT+QNETDEVSTATUS=?", "+QNETDEVSTATUS:", &p_response);
    if (at_response_error(err, p_response))
        asr_style_atc = 1; //EC200T/EC100Y do not support this AT, but RG801/RG500U support 
    safe_at_response_free(p_response);

exit:
    return err;
}

static int atc_deinit(void) {
    return 0;
}

/**
 * Called by atchannel when an unsolicited line appears
 * This is called on atchannel's reader thread. AT commands may
 * not be issued here
 */
static void onUnsolicited (const char *s, const char *sms_pdu)
{
    (void)sms_pdu;

    if (strStartsWith(s, "+QNETDEVSTATUS:")) {
        qmidevice_send_event_to_main(RIL_UNSOL_DATA_CALL_LIST_CHANGED);
    }
    else if (strStartsWith(s, "+CGREG:") || strStartsWith(s, "+C5GREG:")) {
        qmidevice_send_event_to_main(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED);
    }
}

static void * atc_read_thread(void *param) {
    PROFILE_T *profile = (PROFILE_T *)param;
    const char *cdc_wdm = (const char *)profile->qmichannel;
    int wait_for_request_quit = 0;
    int atc_fd;

    atc_fd = cm_open_dev(cdc_wdm);
    if (atc_fd <= 0) {
        dbg_time("fail to open (%s), errno: %d (%s)", cdc_wdm, errno, strerror(errno));
        goto __quit;
    }

    dbg_time("atc_fd = %d", atc_fd);

    if (at_open(atc_fd, onUnsolicited))
        goto __quit;

    qmidevice_send_event_to_main(RIL_INDICATE_DEVICE_CONNECTED);

    while (atc_fd > 0) {
        struct pollfd pollfds[] = {{atc_fd, POLLIN, 0}, {qmidevice_control_fd[1], POLLIN, 0}};
        int ne, ret, nevents = 2;

        ret = poll(pollfds, nevents, wait_for_request_quit ? 1000 : -1);

        if (ret == 0 && wait_for_request_quit) {
            break;
        }

        if (ret < 0) {
            dbg_time("%s poll=%d, errno: %d (%s)", __func__, ret, errno, strerror(errno));
            break;
        }

        for (ne = 0; ne < nevents; ne++) {
            int fd = pollfds[ne].fd;
            short revents = pollfds[ne].revents;

            if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
                dbg_time("%s poll err/hup/inval", __func__);
                dbg_time("epoll fd = %d, events = 0x%04x", fd, revents);
                if (revents & (POLLERR | POLLHUP | POLLNVAL))
                goto __quit;
            }

            if ((revents & POLLIN) == 0)
                continue;

            if (atc_fd == fd) {
                usleep(10*1000); //let atchannel.c read at response.
            }
            else if (fd == qmidevice_control_fd[1]) {
                int triger_event;
                if (read(fd, &triger_event, sizeof(triger_event)) == sizeof(triger_event)) {
                    //dbg_time("triger_event = 0x%x", triger_event);
                    switch (triger_event) {
                        case RIL_REQUEST_QUIT:
                            goto __quit;
                        break;
                        case SIG_EVENT_STOP:
                            wait_for_request_quit = 1;
                        break;
                        default:
                        break;
                    }
                }
            }
        }
    }

__quit:
    at_close();
    qmidevice_send_event_to_main(RIL_INDICATE_DEVICE_DISCONNECTED);
    dbg_time("%s exit", __func__);

    return NULL;
}

const struct qmi_device_ops atc_dev_ops = {
    .init = atc_init,
    .deinit = atc_deinit,
    .read = atc_read_thread,
};

static int requestBaseBandVersion(PROFILE_T *profile) {
    int err;
    ATResponse *p_response = NULL;

    (void)profile;

    err = at_send_command_singleline("AT+CGMR", "\0", &p_response);
    if (at_response_error(err, p_response))
        goto exit;

exit:
    safe_at_response_free(p_response);
    return err;
}

static int requestGetSIMStatus(SIM_Status *pSIMStatus)
{
    int err;
    ATResponse *p_response = NULL;
    char *cpinLine;
    char *cpinResult;
    int ret = SIM_NOT_READY;

    err = at_send_command_singleline("AT+CPIN?", "+CPIN:", &p_response);
    if (at_response_error(err, p_response))
        goto done;

    switch (at_get_cme_error(p_response))
    {
    case CME_SUCCESS:
        break;

    case CME_SIM_NOT_INSERTED:
    case CME_OPERATION_NOT_ALLOWED:
    case CME_FAILURE:
        ret = SIM_ABSENT;
        goto done;

    default:
        ret = SIM_NOT_READY;
        goto done;
    }

    cpinLine = p_response->p_intermediates->line;
    err = at_tok_start (&cpinLine);

    if (err < 0)
    {
        ret = SIM_NOT_READY;
        goto done;
    }

    err = at_tok_nextstr(&cpinLine, &cpinResult);

    if (err < 0)
    {
        ret = SIM_NOT_READY;
        goto done;
    }

    if (0 == strcmp (cpinResult, "SIM PIN"))
    {
        ret = SIM_PIN;
        goto done;
    }
    else if (0 == strcmp (cpinResult, "SIM PUK"))
    {
        ret = SIM_PUK;
        goto done;
    }
    else if (0 == strcmp (cpinResult, "PH-NET PIN"))
    {
        return SIM_NETWORK_PERSONALIZATION;
    }
    else if (0 != strcmp (cpinResult, "READY"))
    {
        /* we're treating unsupported lock types as "sim absent" */
        ret = SIM_ABSENT;
        goto done;
    }

    ret = SIM_READY;

done:
    safe_at_response_free(p_response);
    *pSIMStatus = ret;
    return err;
}

static int requestRegistrationState(UCHAR *pPSAttachedState) {
    int err;
    ATResponse *p_response = NULL;
    ATLine *p_cur;
    int i;
    int cops_atc = -1;
    char *response[3] = {NULL, NULL, NULL};

    *pPSAttachedState = 0;

    err = at_send_command_multiline(
              "AT+COPS=3,0;+COPS?;+COPS=3,1;+COPS?;+COPS=3,2;+COPS?",
              "+COPS:", &p_response);
    if (at_response_error(err, p_response))
        goto error;

    for ( i = 0, p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next, i++) {
        int skip;
        char *line = p_cur->line;

        err = at_tok_start(&line);
        if (err < 0) goto error;

        err = at_tok_nextint(&line, &skip);
        if (err < 0) goto error;

        if (!at_tok_hasmore(&line))
            continue;

        err = at_tok_nextint(&line, &skip);
        if (err < 0) goto error;

        if (!at_tok_hasmore(&line))
            continue;

        err = at_tok_nextstr(&line, &(response[i]));
        if (err < 0) goto error;

        if (!at_tok_hasmore(&line))
            continue;

        err = at_tok_nextint(&line, &cops_atc);
        if (err < 0) goto error;
    }

    if (cops_atc != -1) {
        *pPSAttachedState = 1;
    }

error:
    safe_at_response_free(p_response);

    return err;
}

static int requestSetupDataCall(PROFILE_T *profile, int curIpFamily) {
    int err;
    ATResponse *p_response = NULL;
    char *cmd = NULL;
    ATLine *p_cur = NULL;
    char *line = NULL;
    int pdp = profile->pdp;
    int state = 0;

    (void)curIpFamily;

    if (asr_style_atc) {
        err = at_send_command_multiline("AT+CGACT?", "+CGACT:", &p_response);
        if (at_response_error(err, p_response))
            goto _error;

        for (p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next) {
            int cid = 0;
            line = p_cur->line;

            err = at_tok_start(&line);
            if (err < 0) goto _error;

            err = at_tok_nextint(&line, &cid);
            if (err < 0) goto _error;

            if (cid != pdp)
                continue;

            err = at_tok_nextint(&line, &state);
            if (err < 0) goto _error;
        }
        safe_at_response_free(p_response);

        if (state == 0) {
            asprintf(&cmd, "AT+CGACT=1,%d", pdp);
            err = at_send_command(cmd, &p_response);
            safe_free(cmd);
            if (at_response_error(err, p_response))
                goto _error;
        }
    }

    if(asr_style_atc)
        asprintf(&cmd, "AT+QNETDEVCTL=1,%d,%d", pdp, 1);
    else
        asprintf(&cmd, "AT+QNETDEVCTL=%d,1,%d", pdp, 0);
    err = at_send_command(cmd, &p_response);
    safe_free(cmd);

    if (at_response_error(err, p_response))
        goto _error;

    if (!asr_style_atc) { //TODO some modems do not sync return setup call resule
        int t = 0;

        asprintf(&cmd, "AT+QNETDEVSTATUS=%d", pdp);
        while (t++ < 30) {
            err = at_send_command_singleline(cmd, "+QNETDEVSTATUS", &p_response);

            if (!at_response_error(err, p_response)) {
                safe_at_response_free(p_response);
                break;
            }
            safe_at_response_free(p_response);
            sleep(1);
        }
        safe_free(cmd);
        if (t > 15)
            goto _error;
    }
    //some modem do not report URC
    qmidevice_send_event_to_main(RIL_UNSOL_DATA_CALL_LIST_CHANGED);

_error:
    safe_at_response_free(p_response);
    dbg_time("%s err=%d", __func__, err);
    return err;
}

static int at_netdevstatus(int pdp, unsigned int *pV4Addr) {
    int err;
    ATResponse *p_response = NULL;
    char *cmd = NULL;
    char *line;
    char *ipv4 = NULL;

    *pV4Addr = 0;

    asprintf(&cmd, "AT+QNETDEVSTATUS=%d", pdp);
    err = at_send_command_singleline(cmd, "+QNETDEVSTATUS", &p_response);
    safe_free(cmd);
    if (at_response_error(err, p_response))
        goto _error;

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0)
        goto _error;

    err = at_tok_nextstr(&line, &ipv4);
    if (err < 0) goto _error;

    if (ipv4) {
        int addr[4] = {0, 0, 0, 0};

        sscanf(ipv4, "%d.%d.%d.%d", &addr[0], &addr[1], &addr[2], &addr[3]);
        *pV4Addr = (addr[0]) | (addr[1]<<8) | (addr[2]<<16) | (addr[3]<<24);
    }

_error:
    return err;
}

static int requestQueryDataCall(UCHAR  *pConnectionStatus, int curIpFamily) {
    int err;
    ATResponse *p_response = NULL;
    ATLine *p_cur = NULL;
    char *line = NULL;
    int state = 0;
    int bind = 0;
    int cid;
    int pdp = 1;
    unsigned int v4Addr = 0;

    (void)curIpFamily;

    *pConnectionStatus = QWDS_PKT_DATA_DISCONNECTED;

    if (asr_style_atc)
        goto _asr_style_atc;
    
    err = at_netdevstatus(pdp, &v4Addr);
    if (!err && v4Addr) {
        *pConnectionStatus = QWDS_PKT_DATA_CONNECTED;
        //if (profile->ipv4.Address == 0) {} //TODO
     }
    goto _error;

_asr_style_atc:
    err = at_send_command_multiline("AT+QNETDEVCTL?", "+QNETDEVCTL:", &p_response);
    if (at_response_error(err, p_response))
        goto _error;

    for (p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next)
    {
        int tmp;
        //+QNETDECTL:<op>,<cid>,<urc_en>,<state>

        line = p_cur->line;
        err = at_tok_start(&line);
        if (err < 0)
            goto _error;

        err = at_tok_nextint(&line, &bind);
        if (err < 0)
            goto _error;

        err = at_tok_nextint(&line, &cid);
        if (err < 0)
            goto _error;

        if (cid != pdp)
            continue;

        err = at_tok_nextint(&line, &tmp);
        if(err < 0)
            goto _error;

        err = at_tok_nextint(&line, &state);
        if(err < 0)
            goto _error;
    }
    safe_at_response_free(p_response);

    if (bind == 0 || state == 0)
        goto _error;

    err = at_send_command_multiline("AT+CGACT?", "+CGACT:", &p_response);
    if (at_response_error(err, p_response))
        goto _error;

    for (p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next)
    {
        line = p_cur->line;
        err = at_tok_start(&line);
        if (err < 0)
            goto _error;

        err = at_tok_nextint(&line, &cid);
        if (err < 0)
            goto _error;

        if (cid != pdp)
            continue;

        err = at_tok_nextint(&line, &state);
        if (err < 0)
            goto _error;
    }
    safe_at_response_free(p_response);

    if (bind && state)
        *pConnectionStatus = QWDS_PKT_DATA_CONNECTED;

_error:
    safe_at_response_free(p_response);
    dbg_time("%s err=%d, call_state=%d", __func__, err, *pConnectionStatus);
    return err;
}

static int requestDeactivateDefaultPDP(PROFILE_T *profile, int curIpFamily) {
    int err;
    char *cmd = NULL;
    int pdp = profile->pdp;

    (void)curIpFamily;

    if (asr_style_atc)
        asprintf(&cmd, "AT+QNETDEVCTL=0,%d,%d", pdp, 0);
    else
        asprintf(&cmd, "AT+QNETDEVCTL=%d,0,%d", pdp, 0);
    err = at_send_command(cmd, NULL);
    safe_free(cmd);

    dbg_time("%s err=%d", __func__, err);
    return err;
}

static int requestGetIPAddress(PROFILE_T *profile, int curIpFamily) {
    int err;
    ATResponse *p_response = NULL;
    char *cmd = NULL;
    ATLine *p_cur = NULL;
    char *line = NULL;
    int pdp = profile->pdp;
    unsigned int v4Addr = 0;

    (void)curIpFamily;

    if (asr_style_atc)
        goto _asr_style_atc;   

    err = at_netdevstatus(pdp, &v4Addr);
    if (err < 0) goto _error;

    goto _error;

_asr_style_atc:
    asprintf(&cmd, "AT+CGPADDR=%d", profile->pdp);
    err = at_send_command_singleline(cmd, "+CGPADDR:", &p_response);
    safe_free(cmd);
    if (at_response_error(err, p_response))
        goto _error;

    //+CGPADDR: 1,"10.201.80.91","2409:8930:4B3:41C7:F9B8:3D9B:A2F7:CA96"
    for (p_cur = p_response->p_intermediates; p_cur != NULL; p_cur = p_cur->p_next)
    {
        char *ipv4 = NULL;

        line = p_cur->line;
        err = at_tok_start(&line);
        if (err < 0)
            goto _error;

        err = at_tok_nextint(&line, &pdp);
        if (err < 0)
            goto _error;

        if (pdp != profile->pdp)
            continue;

        if (!at_tok_hasmore(&line))
            continue;

        err = at_tok_nextstr(&line, &ipv4);
        if (err < 0) goto _error;

        if (ipv4) {
            int addr[4] = {0, 0, 0, 0};

            sscanf(ipv4, "%d.%d.%d.%d", &addr[0], &addr[1], &addr[2], &addr[3]);
            v4Addr = (addr[0]) | (addr[1]<<8) | (addr[2]<<16) | (addr[3]<<24);
            break;
        }
    }

_error:
    if (!v4Addr && !err) {
        err = -1;
    }
    if (profile->ipv4.Address != v4Addr) {
        profile->ipv4.Address = v4Addr;
        if (v4Addr) {
            unsigned char *v4 = (unsigned char *)&v4Addr;
            dbg_time("%s %d.%d.%d.%d", __func__, v4[0], v4[1], v4[2], v4[3]);    
        }
    }
        
    dbg_time("%s err=%d", __func__, err);
    return err;
}

static int requestGetICCID(void) {
    int err;
    ATResponse *p_response = NULL;
    char *line;
    char *iccid;

    err = at_send_command_singleline("AT+QCCID", "+QCCID:", &p_response);
    if (at_response_error(err, p_response))
        goto _error;

    line = p_response->p_intermediates->line;
    err = at_tok_start(&line);
    if (err < 0)
        goto _error;

    err = at_tok_nextstr(&line, &iccid);
    if (err < 0)
        goto _error;

    dbg_time("%s %s", __func__, iccid);

_error:
    safe_at_response_free(p_response);
    return err;
}

static int requestGetIMSI(void) {
    int err;
    ATResponse *p_response = NULL;
    char *imsi;

    err = at_send_command_numeric("AT+CIMI", &p_response);
    if (at_response_error(err, p_response))
        goto exit;

    imsi = p_response->p_intermediates->line;
    if (imsi) {
        dbg_time("%s %s", __func__, imsi);
    }

exit:
    safe_at_response_free(p_response);
    return err;
}

const struct request_ops atc_request_ops = {
    .requestBaseBandVersion = requestBaseBandVersion,
    .requestGetSIMStatus = requestGetSIMStatus,
    .requestRegistrationState = requestRegistrationState,
    .requestSetupDataCall = requestSetupDataCall,
    .requestQueryDataCall = requestQueryDataCall,
    .requestDeactivateDefaultPDP = requestDeactivateDefaultPDP,
    .requestGetIPAddress = requestGetIPAddress,
    .requestGetICCID = requestGetICCID,
    .requestGetIMSI = requestGetIMSI,
};

