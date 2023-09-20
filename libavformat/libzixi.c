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
#include <sys/time.h>

#include "libavutil/avassert.h"
#include "libavutil/opt.h"
#include "libavutil/parseutils.h"
#include "libavutil/time.h"

#include "avformat.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"

enum ZixiModeType {
    ZIXI_RECEIVER_CONNECT_MODE = 0,
    ZIXI_RECEIVER_ACCEPT_MODE = 1,
    ZIXI_FEEDER_MODE = 2
};

enum ZixiEncryptionType
{
    ZIXI_NONE_ENCRYPTION = 0,
    ZIXI_AES_128_ENCRYPTION,
    ZIXI_AES_192_ENCRYPTION,
    ZIXI_AES_256_ENCRYPTION,
    ZIXI_CHACHA20_ENCRYPTION, // fast cipher for platforms without AES-NI
};


#define ZIXI_FRAME_SIZE 1316

static const int ZixiFrameSize = ZIXI_FRAME_SIZE;

typedef struct ZixiContext {
    const AVClass *class;
    ZIXI_CALLBACKS callbacks;
    ZIXI_STREAM_INFO info;
    void* streamHandle;
    char* receiverId;
    int64_t latency;
    char *password;
    enum ZixiModeType mode;
    enum ZixiEncryptionType encryption;
    char *encryptionKey;

    char* streamId;
    zixi_stream_config streamConfig;

    uint8_t frame[ZIXI_FRAME_SIZE];
    int frameSize;

    int fd;
} ZixiContext;

#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
#define OFFSET(x) offsetof(ZixiContext, x)

static const AVOption libzixi_options[] = {
    { "receiverId", "Is a unique identifier of the unit (for receiver modes only)", OFFSET(receiverId), AV_OPT_TYPE_STRING, { .str = NULL }, .flags = D|E },
    { "latency",    "receiver delay (in microseconds) to absorb bursts of missed packet retransmissions", OFFSET(latency), AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "password",   "this is the password for the stream", OFFSET(password),  AV_OPT_TYPE_STRING, { .str = NULL }, .flags = D|E },
    { "mode",       "Connection mode (receiver connect, receiver accept, feeder)", OFFSET(mode), AV_OPT_TYPE_INT, { .i64 = ZIXI_RECEIVER_CONNECT_MODE }, ZIXI_RECEIVER_CONNECT_MODE, ZIXI_FEEDER_MODE, .flags = D|E, "mode" },
    { "connect",    NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = ZIXI_RECEIVER_CONNECT_MODE }, INT_MIN, INT_MAX, .flags = D|E, "mode" },
    { "accept",     NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = ZIXI_RECEIVER_ACCEPT_MODE },  INT_MIN, INT_MAX, .flags = D|E, "mode" },
    { "feeder",     NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = ZIXI_FEEDER_MODE }, INT_MIN, INT_MAX, .flags = D|E, "mode" },
    { "streamId",   "Stream name on the broadcaster (feeder mode only)", OFFSET(streamId), AV_OPT_TYPE_STRING, { .str = NULL }, .flags = D|E },
    { "enc",        "Encryption type. Options are AES128/192/256 or CHACHA20", OFFSET(encryption), AV_OPT_TYPE_INT, { .i64 = ZIXI_NONE_ENCRYPTION }, ZIXI_NONE_ENCRYPTION, ZIXI_CHACHA20_ENCRYPTION, .flags = D|E, "enc" },
    { "none",       NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = ZIXI_NONE_ENCRYPTION },     INT_MIN, INT_MAX, .flags = D|E, "enc" },
    { "aes128",     NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = ZIXI_AES_128_ENCRYPTION },  INT_MIN, INT_MAX, .flags = D|E, "enc" },
    { "aes192",     NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = ZIXI_AES_192_ENCRYPTION },  INT_MIN, INT_MAX, .flags = D|E, "enc" },
    { "aes256",     NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = ZIXI_AES_256_ENCRYPTION },  INT_MIN, INT_MAX, .flags = D|E, "enc" },
    { "chacha20",   NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = ZIXI_CHACHA20_ENCRYPTION }, INT_MIN, INT_MAX, .flags = D|E, "enc" },
    { "key",        "Encryption key - string of hex digits", OFFSET(encryptionKey),  AV_OPT_TYPE_STRING, { .str = NULL }, .flags = D|E },
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

static void encoder_feedback(int bps, bool iframe, void* data)
{
    av_log(data, AV_LOG_INFO, "encoder_feedback: set %d\n", bps);
}

static ZIXI_ENCRYPTION libzixi_get_encryption(enum ZixiEncryptionType encryption)
{
    ZIXI_ENCRYPTION result;
    result = ZIXI_NO_ENCRYPTION;

    if (encryption == ZIXI_AES_128_ENCRYPTION)
    {
        result = ZIXI_AES_128;
    }
    else if (encryption == ZIXI_AES_192_ENCRYPTION)
    {
        result = ZIXI_AES_192;
    }
    else if (encryption == ZIXI_AES_256_ENCRYPTION)
    {
        result = ZIXI_AES_256;
    }
    else if (encryption == ZIXI_CHACHA20_ENCRYPTION)
    {
        result = ZIXI_CHACHA20;
    }

    return result;
}

static int libzixi_open(URLContext *h, const char *uri, int flags)
{
    int ret = 0;
    ZixiContext *context = h->priv_data;
    char buf[256];
    char hostname[1024], proto[20], path[1024];
    int port = -1;
    const char* user;
    const char* session;
    const char* p;
    char* streamIdPointer;

    context->frameSize = 0;
    context->mode = ZIXI_RECEIVER_CONNECT_MODE;

    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
                  &port, path, sizeof(path), uri);
    if (strcmp(proto, "zixi"))
    {
        return AVERROR(EINVAL);
    }

    if (strcmp(hostname, "0.0.0.0") == 0)
    {
        if (port <= 0 || port >= 65536) {
            av_log(h, AV_LOG_ERROR, "Port missing in uri\n");
            return AVERROR(EINVAL);
        }

        context->mode = ZIXI_RECEIVER_ACCEPT_MODE;
    }

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
        if (av_find_info_tag(buf, sizeof(buf), "mode", p)) {
            if (!strcmp(buf, "connect")) {
                context->mode = ZIXI_RECEIVER_CONNECT_MODE;
            } else if (!strcmp(buf, "accept")) {
                context->mode = ZIXI_RECEIVER_ACCEPT_MODE;
            } else if (!strcmp(buf, "feeder")) {
                context->mode = ZIXI_FEEDER_MODE;
            } else {
                return AVERROR(EINVAL);
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "streamId", p)) {
            av_freep(&context->streamId);
            context->streamId = av_strndup(buf, strlen(buf));
        }
        if (av_find_info_tag(buf, sizeof(buf), "enc", p)) {
            if (!strcmp(buf, "none")) {
                context->encryption = ZIXI_NONE_ENCRYPTION;
            } else if (!strcmp(buf, "aes128")) {
                context->encryption = ZIXI_AES_128_ENCRYPTION;
            } else if (!strcmp(buf, "aes192")) {
                context->encryption = ZIXI_AES_192_ENCRYPTION;
            } else if (!strcmp(buf, "aes256")) {
                context->encryption = ZIXI_AES_256_ENCRYPTION;
            } else if (!strcmp(buf, "chacha20")) {
                context->encryption = ZIXI_CHACHA20_ENCRYPTION;
            } else {
                return AVERROR(EINVAL);
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "key", p)) {
            av_freep(&context->encryptionKey);
            context->encryptionKey = av_strndup(buf, strlen(buf));
        }
    }

    zixi_client_configure_logging(ZIXI_LOG_WARNINGS, libzixi_logger, (void*)h);

    if (context->mode == ZIXI_FEEDER_MODE)
    {
        int streamIdLength = strlen(path);
        if (streamIdLength > 0)
        {
            p = strchr(path, '?');
            if (p)
            {
                streamIdLength -= strlen(p);
            }

            streamIdPointer = path;
            if (path[0] == '/')
            {
                ++streamIdPointer;
                --streamIdLength;
            }

            if (streamIdLength > 0)
            {
                strncpy(buf, streamIdPointer, streamIdLength);
                buf[streamIdLength] = 0;
                av_freep(&context->streamId);
                context->streamId = av_strndup(buf, strlen(buf));
            }
        }

        user = context->receiverId == NULL ? "" : context->receiverId;
        session = context->password == NULL ? "" : context->password;
        ret = zixi_configure_credentials(user, strlen(user), session, strlen(session));
        if(ret != ZIXI_ERROR_OK)
        {
            av_log(h, AV_LOG_ERROR, "Failed to configure credentials. Error: %d\n", ret);
            return AVERROR_UNKNOWN;
        }

        ret = zixi_prepare_configuration(&context->streamConfig, NULL, NULL);
        if(ret != ZIXI_ERROR_OK)
        {
            av_log(h, AV_LOG_ERROR, "Failed zixi_prepare_configuration. Error: %d\n", ret );
            return AVERROR_UNKNOWN;
        }

        context->streamConfig.sz_enc_key = context->encryptionKey;
        context->streamConfig.enc_type = libzixi_get_encryption(context->encryption);
        context->streamConfig.fast_connect = 0;
        context->streamConfig.max_bitrate = 50000 * 1000;
        context->streamConfig.max_latency_ms = 10000;
        context->streamConfig.port = (unsigned short*) malloc( 1 * sizeof(unsigned short));
        context->streamConfig.port[0] = port;
        context->streamConfig.sz_stream_id = context->streamId;
        context->streamConfig.stream_id_max_length = strlen(context->streamConfig.sz_stream_id);
        context->streamConfig.sz_hosts = (char**) malloc ( 1* sizeof(char*));
        context->streamConfig.hosts_len = (int*) malloc (1 * sizeof(int));
        context->streamConfig.sz_hosts[0] = hostname; // broadcaster address
        context->streamConfig.hosts_len[0] = strlen(context->streamConfig.sz_hosts[0]);
        context->streamConfig.reconnect = 1;
        context->streamConfig.num_hosts = 1;
        context->streamConfig.use_compression = 1;
        context->streamConfig.rtp = 0;
        context->streamConfig.fec_overhead = 15;
        context->streamConfig.content_aware_fec = false;
        context->streamConfig.fec_block_ms = 30;
        context->streamConfig.timeout = 0;
        context->streamConfig.limited = (ZIXI_ADAPTIVE_MODE)ZIXI_ADAPTIVE_FEC;
        context->streamConfig.smoothing_latency = 0;
        context->streamConfig.enforce_bitrate = 0;
        context->streamConfig.force_bonding = 0;
        context->streamConfig.allow_arq = 1;
        context->streamConfig.protocol = ZIXI_PROTOCOL_UDP;

        context->streamConfig.num_local_nics = 0;
        context->streamConfig.force_bonding = 1;
        context->streamConfig.local_nics = 0;

        context->streamConfig.ignore_dtls_cert_error = 0;

        if (context->streamConfig.limited== ZIXI_ADAPTIVE_ENCODER)
        {
            encoder_control_info enc;
            enc.max_bitrate = 50000 *8/10 * 1000;
            enc.min_bitrate = 200 * 1000;
            enc.aggressiveness = 10;
            enc.update_interval = 0;
            enc.setter = encoder_feedback;
            enc.param = (void*)h;
            context->streamConfig.force_padding = true;

            ret = zixi_open_stream(context->streamConfig, &enc, &context->streamHandle);
        }
        else
        {
            ret = zixi_open_stream(context->streamConfig, NULL, &context->streamHandle);
        }

        if(ret != ZIXI_ERROR_OK)
        {
            av_log(h, AV_LOG_ERROR, "Failed to open stream. Error: %d\n", ret );
            return AVERROR_UNKNOWN;
        }
        av_log(h, AV_LOG_INFO, "Stream is opened\n");
    }
    else
    {
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

        ret = zixi_init_connection_handle(&context->streamHandle);
        if (ret != 0)
        {
            av_log(h, AV_LOG_ERROR, "zixi_init_connection_handle ERROR - %d\n", ret);
            zixi_delete_connection_handle(context->streamHandle);
            zixi_destroy();
            return AVERROR_UNKNOWN;
        }

        ret = zixi_configure_id(context->streamHandle,
                                 context->receiverId == NULL ? "" : context->receiverId,
                                 context->password == NULL ? "" : context->password);
        if (ret != 0)
        {
            av_log(h, AV_LOG_ERROR, "zixi_configure_id ERROR - %d\n", ret);
            zixi_delete_connection_handle(context->streamHandle);
            zixi_destroy();
            return AVERROR_UNKNOWN;
        }

        bool fec = false;
        unsigned int fec_overhead = 30;
        unsigned int fec_block_ms = 50;
        bool fec_content_aware = false;

        zixi_configure_error_correction(context->streamHandle, context->latency / 1000, ZIXI_LATENCY_STATIC, fec ? ZIXI_FEC_ON : ZIXI_FEC_OFF, fec_overhead, fec_block_ms, fec_content_aware, false, 0, false, ZIXI_ARQ_ON);

        if (context->encryptionKey)
        {
            ret = zixi_configure_decryption(context->streamHandle, libzixi_get_encryption(context->encryption), context->encryptionKey);
            if (ret != 0)
            {
                av_log(h, AV_LOG_ERROR, "zixi_configure_decryption ERROR - %d\n", ret);
            }
        }

        if (context->mode == ZIXI_RECEIVER_CONNECT_MODE)
        {
            ret = zixi_connect_url(context->streamHandle, uri, true, context->callbacks, true, false, true, "");

            if (ret != ZIXI_ERROR_OK)
            {
                int ex_ret = zixi_get_last_error(context->streamHandle);
                av_log(h, AV_LOG_ERROR, "zixi_connect_url ERROR - %d, last error - %d\n", ret, ex_ret);
                zixi_delete_connection_handle(context->streamHandle);
                zixi_destroy();
                return AVERROR_UNKNOWN;
            }

            ret = zixi_query_stream_info(context->streamHandle, &context->info);
            if (ret != ZIXI_ERROR_OK)
            {
                av_log(h, AV_LOG_ERROR, "zixi_query_stream_info ERROR - %d\n", ret);
                zixi_disconnect(context->streamHandle);
                zixi_delete_connection_handle(context->streamHandle);
                zixi_destroy();
                return AVERROR_UNKNOWN;
            }
        }
        else if (context->mode == ZIXI_RECEIVER_ACCEPT_MODE)
        {
            zixi_disconnect(context->streamHandle);
            ret = zixi_accept(context->streamHandle, port, context->callbacks, true, ZIXI_PROTOCOL_UDP);
            av_log(h, AV_LOG_ERROR, "zixi_accept ERROR - %d\n", ret);
        }
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
        ret = zixi_read(context->streamHandle, (char*)buf, size, &bytes_read, &is_eof, &discontinuity, false, &bitrate);
        if (ret != ZIXI_ERROR_NOT_READY && ret != ZIXI_ERROR_OK)
        {
            av_log(h, AV_LOG_ERROR, "zixi_read ERROR - %d\n", ret);
            return AVERROR(EIO);
        }
    } while (ret != ZIXI_ERROR_OK);

    return bytes_read;
}

static unsigned long getTickCount(void)
{
#ifndef WIN32
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
#else
    return GetTickCount();
#endif
}

static int libzixi_write(URLContext *h, const uint8_t *buf, int size)
{
    ZixiContext *context = h->priv_data;
    int ret = 0;
    int offset = 0;
    int resultSize = size;
    unsigned long now;

    if (context->frameSize > 0)
    {
        int copySize = (size < ZixiFrameSize - context->frameSize) ? size : (ZixiFrameSize - context->frameSize);
        offset = copySize;
        memcpy(context->frame + context->frameSize, buf, ZixiFrameSize - context->frameSize);
        size -= copySize;
        context->frameSize += copySize;

        if (context->frameSize == ZixiFrameSize)
        {
            context->frameSize = 0;
            now = getTickCount();
            ret = zixi_send_frame(context->streamHandle, context->frame, ZixiFrameSize,
                                   (context->streamConfig.rtp || context->streamConfig.smoothing_latency) ? 0 : now * 90);
            if (ret == ZIXI_ERROR_OK)
            {
                ret = 0;
            }
            else
            {
                av_log(h, AV_LOG_ERROR, "zixi_write ERROR - %d %d\n", ret, size);
                return AVERROR(EIO);
            }
        }
    }

    while(size)
    {
        if (size >= ZixiFrameSize)
        {
            size -= ZixiFrameSize;
            context->frameSize = 0;
        }
        else
        {
            context->frameSize = size;
            memcpy(context->frame, buf + offset, size);
            break;
        }

        now = getTickCount();
        ret = zixi_send_frame(context->streamHandle, buf + offset, ZixiFrameSize, (context->streamConfig.rtp || context->streamConfig.smoothing_latency) ? 0 : now * 90);
        if (ret == ZIXI_ERROR_OK)
        {
            ret = 0;
        }
        else
        {
            av_log(h, AV_LOG_ERROR, "zixi_write ERROR - %d %d\n", ret, size);
            return AVERROR(EIO);
        }

        offset += ZixiFrameSize;
    }

    return resultSize;
}

static int libzixi_close(URLContext *h)
{
    ZixiContext *context = h->priv_data;
    int ret = 0;

    if (context->mode == ZIXI_FEEDER_MODE)
    {
        ret = zixi_close_stream(context->streamHandle);
        if(ret != ZIXI_ERROR_OK)
        {
            av_log(h, AV_LOG_ERROR, "Failed to close stream\n");
            return AVERROR_UNKNOWN;
        }

        av_freep(&context->streamId);
    }
    else
    {
        ret = zixi_disconnect(context->streamHandle);
        if (ret != ZIXI_ERROR_OK)
        {
            av_log(h, AV_LOG_ERROR, "zixi_disconnect ERROR - %d\n", ret);
        }

        zixi_delete_connection_handle(context->streamHandle);
        if (ret != ZIXI_ERROR_OK)
        {
            av_log(h, AV_LOG_ERROR, "zixi_delete_connection_handle ERROR - %d\n", ret);
        }

        zixi_destroy();

        av_freep(&context->receiverId);
    }

    av_freep(&context->encryptionKey);
    av_freep(&context->password);

    return 0;
}

static int libzixi_get_file_handle(URLContext *h)
{
    ZixiContext *context = h->priv_data;
    return context->fd;
}

int av_get_zixi_statistics(AVFormatContext *context, int* latency, double* rtt, int* droppedPackets)
{
    int ret;
    ZIXI_NETWORK_STATS net_stats;
    //ZIXI_CONNECTION_STATS con_stats;
    //ZIXI_ERROR_CORRECTION_STATS error_correction_stats;

    if (context == NULL || context->pb == NULL
        || context->pb->opaque == NULL)
        return 0;

    if (strstr(context->url, "zixi://") != context->url)
        return 0;

    URLContext *u = context->pb->opaque;
    ZixiContext *s = u->priv_data;

    if (s == NULL)
        return 0;

    ret = zixi_query_statistics(s->streamHandle, NULL, &net_stats, NULL);
    if (ret != ZIXI_ERROR_OK)
    {
        av_log(u, AV_LOG_ERROR, "zixi_query_statistics ERROR - %d\n", ret);
        return 0;
    }

    if (latency)
        *latency = net_stats.latency;
    if (rtt)
        *rtt = net_stats.rtt;
    if (droppedPackets)
        *droppedPackets = net_stats.dropped;

    return 1;
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
