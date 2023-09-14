/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file
 * Zixi protocol
 */

#include <zixi_definitions.h>
#include <zixi_feeder_interface.h>
#include <zixi_client_interface.h>

#include <string.h>

#include "libavutil/avassert.h"
#include "libavutil/opt.h"
#include "libavutil/parseutils.h"
#include "libavutil/time.h"

#include "avformat.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"

/* This is for MPEG-TS and it's a default SRTO_PAYLOADSIZE for SRTT_LIVE (8 TS packets) */
#ifndef SRT_LIVE_DEFAULT_PAYLOAD_SIZE
#define SRT_LIVE_DEFAULT_PAYLOAD_SIZE 1316
#endif

/* This is the maximum payload size for Live mode, should you have a different payload type than MPEG-TS */
#ifndef SRT_LIVE_MAX_PAYLOAD_SIZE
#define SRT_LIVE_MAX_PAYLOAD_SIZE 1456
#endif

enum SRTMode {
    SRT_MODE_CALLER = 0,
    SRT_MODE_LISTENER = 1,
    SRT_MODE_RENDEZVOUS = 2
};

typedef struct ZixiContext {
    const AVClass *class;
    ZIXI_CALLBACKS callbacks;
    ZIXI_STREAM_INFO info;
    void* zixi_handle;
    char* receiverId;
    int64_t latency;
    char *password;

    int fd;
} ZixiContext;

#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
#define OFFSET(x) offsetof(ZixiContext, x)

static const AVOption libzixi_options[] = {
    { "receiverId",  "Is a unique identifier of the unit", OFFSET(receiverId), AV_OPT_TYPE_STRING, { .str = NULL }, .flags = D|E },
    { "latency",     "receiver delay (in microseconds) to absorb bursts of missed packet retransmissions", OFFSET(latency), AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "password",    "this is the password for the stream", OFFSET(password),  AV_OPT_TYPE_STRING, { .str = NULL }, .flags = D|E },
    { NULL }
};

static void libzixi_logger(void* user_data, int level, const char* str)
{
    av_log(user_data, AV_LOG_INFO, "%s\n", str);
}

static void libzixi_status_changed_handler(void *handle, ZIXI_STATUS status, void *user_data)
{
    int err = zixi_get_last_error(handle);

    switch (status)
    {
    case ZIXI_DISCONNECTED:
        av_log(user_data, AV_LOG_INFO, "Disconnected\n");
        break;
    case ZIXI_CONNECTING:
        av_log(user_data, AV_LOG_INFO, "ZIXI_STATUS -> ZIXI_CONNECTING\n");
        break;
    case ZIXI_CONNECTED:
        av_log(user_data, AV_LOG_INFO, "ZIXI_STATUS -> ZIXI_CONNECTED\n");
        break;
    case ZIXI_DISCONNECTING:
        av_log(user_data, AV_LOG_INFO, "ZIXI_STATUS -> ZIXI_DISCONNECTING\n");
        break;
    case ZIXI_RECONNECTING:
        av_log(user_data, AV_LOG_INFO, "ZIXI_STATUS -> ZIXI_RECONNECTING\n");
        break;
    default:
        av_log(user_data, AV_LOG_INFO, "ZIXI_STATUS -> UNKNOWN[status=%d]\n", status);
        break;
    }

    if (err != 0)
    {
        av_log(user_data, AV_LOG_ERROR, "Error=%d\n", err);
    }
}

static void libzixi_stream_info_handler(void *handle, ZIXI_STREAM_INFO info, void *user_data)
{
}

static int libzixi_open(URLContext *h, const char *uri, int flags)
{
    int ret = 0;
    ZixiContext *context = h->priv_data;

    const char * p;
    char buf[256];
    p = strchr(uri, '?');
    if (p)
    {
        if (av_find_info_tag(buf, sizeof(buf), "receiverId", p)) {
            av_freep(&context->receiverId);
            context->receiverId = av_strndup(buf, strlen(buf));
        }
        if (av_find_info_tag(buf, sizeof(buf), "latency", p)) {
            context->latency = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "password", p)) {
            av_freep(&context->password);
            context->password = av_strndup(buf, strlen(buf));
        }
    }

    zixi_client_configure_logging(ZIXI_LOG_WARNINGS, libzixi_logger, (void*)h);
    context->callbacks.zixi_new_stream = libzixi_stream_info_handler;
    context->callbacks.zixi_status_changed = libzixi_status_changed_handler;
    context->callbacks.zixi_bitrate_changed = NULL;
    context->callbacks.user_data = (void*)h;

    ret = zixi_init();
    if (ret != 0)
    {
        av_log(h, AV_LOG_ERROR, "zixi_init ERROR - %d\n", ret);
        zixi_destroy();
        return AVERROR_UNKNOWN;
    }

    ret = zixi_init_connection_handle(&context->zixi_handle);
    if (ret != 0)
    {
        av_log(h, AV_LOG_ERROR, "zixi_init_connection_handle ERROR - %d\n", ret);
        zixi_delete_connection_handle(context->zixi_handle);
        zixi_destroy();
        return AVERROR_UNKNOWN;
    }

    //"ip-172-31-29-229"
    ret = zixi_configure_id(context->zixi_handle,
                             context->receiverId == NULL ? "" : context->receiverId,
                             context->password == NULL ? "" : context->password);
    if (ret != 0)
    {
        av_log(h, AV_LOG_ERROR, "zixi_configure_id ERROR - %d\n", ret);
        zixi_delete_connection_handle(context->zixi_handle);
        zixi_destroy();
        return AVERROR_UNKNOWN;
    }

    bool fec               = false;
    unsigned int fec_overhead      = 30;
    unsigned int fec_block_ms      = 50;
    bool fec_content_aware = false;

    zixi_configure_error_correction(context->zixi_handle, context->latency / 1000, ZIXI_LATENCY_STATIC, fec ? ZIXI_FEC_ON : ZIXI_FEC_OFF, fec_overhead, fec_block_ms, fec_content_aware, false, 0, false, ZIXI_ARQ_ON);

    ret = zixi_connect_url(context->zixi_handle, uri, true, context->callbacks, true, false, true, "");

    if (ret != ZIXI_ERROR_OK)
    {
        int ex_ret = zixi_get_last_error(context->zixi_handle);
        av_log(h, AV_LOG_ERROR, "zixi_connect_url ERROR - %d, last error - %d\n", ret, ex_ret);
        zixi_delete_connection_handle(context->zixi_handle);
        zixi_destroy();
        return AVERROR_UNKNOWN;
    }

    ret = zixi_query_stream_info(context->zixi_handle, &context->info);
    if (ret != ZIXI_ERROR_OK)
    {
        av_log(h, AV_LOG_ERROR, "zixi_query_stream_info ERROR - %d\n", ret);
        zixi_disconnect(context->zixi_handle);
        zixi_delete_connection_handle(context->zixi_handle);
        zixi_destroy();
        return AVERROR_UNKNOWN;
    }

    return 0;
}

static int libzixi_read(URLContext *h, uint8_t *buf, int size)
{
    ZixiContext *context = h->priv_data;
    int ret = 0;

    unsigned int bytes_read = 0;
    bool is_eof;
    bool discontinuity;
    int bitrate;
    do {
        ret = zixi_read(context->zixi_handle, (char*)buf, size, &bytes_read, &is_eof, &discontinuity, false, &bitrate);
        if (ret != ZIXI_ERROR_NOT_READY && ret != ZIXI_ERROR_OK)
        {
            av_log(h, AV_LOG_ERROR, "zixi_read ERROR - %d\n", ret);
            break;
        }
    } while (ret != ZIXI_ERROR_OK);

    return bytes_read;
}

static int libzixi_write(URLContext *h, const uint8_t *buf, int size)
{
    int ret = AVERROR_UNKNOWN;

    return ret;
}

static int libzixi_close(URLContext *h)
{
    ZixiContext *context = h->priv_data;
    int ret = 0;

    ret = zixi_disconnect(context->zixi_handle);
    if (ret != ZIXI_ERROR_OK)
    {
        av_log(h, AV_LOG_ERROR, "zixi_disconnect ERROR - %d\n", ret);
    }

    zixi_delete_connection_handle(context->zixi_handle);
    if (ret != ZIXI_ERROR_OK)
    {
        av_log(h, AV_LOG_ERROR, "zixi_delete_connection_handle ERROR - %d\n", ret);
    }

    zixi_destroy();

    return 0;
}

static int libzixi_get_file_handle(URLContext *h)
{
    ZixiContext *context = h->priv_data;
    return context->fd;
}

int av_get_srt_statistics(AVFormatContext *context, int* latency, double* rtt, int* droppedPackets)
{
    return 0;
}

static const AVClass libzixi_class = {
    .class_name = "libzixi",
    .item_name  = av_default_item_name,
    .option     = libzixi_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_libzixi_protocol = {
    .name                = "zixi",
    .url_open            = libzixi_open,
    .url_read            = libzixi_read,
    .url_write           = libzixi_write,
    .url_close           = libzixi_close,
    .url_get_file_handle = libzixi_get_file_handle,
    .priv_data_size      = sizeof(ZixiContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &libzixi_class,
};
