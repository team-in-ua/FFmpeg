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

#include "libavutil/avassert.h"
#include "libavutil/samplefmt.h"
#include "libavutil/pixfmt.h"
#include "libavcodec/avcodec.h"
#include "avdevice.h"
#include "internal.h"
#include "config.h"

#include "libavutil/ffversion.h"
const char av_device_ffversion[] = "FFmpeg version " FFMPEG_VERSION;

#if FF_API_DEVICE_CAPABILITIES
const AVOption av_device_capabilities[] = {
    { NULL }
};
#endif

unsigned avdevice_version(void)
{
    av_assert0(LIBAVDEVICE_VERSION_MICRO >= 100);
    return LIBAVDEVICE_VERSION_INT;
}

const char * avdevice_configuration(void)
{
    return FFMPEG_CONFIGURATION;
}

const char * avdevice_license(void)
{
#define LICENSE_PREFIX "libavdevice license: "
    return &LICENSE_PREFIX FFMPEG_LICENSE[sizeof(LICENSE_PREFIX) - 1];
}

int avdevice_app_to_dev_control_message(struct AVFormatContext *s, enum AVAppToDevMessageType type,
                                        void *data, size_t data_size)
{
    if (!s->oformat || !s->oformat->control_message)
        return AVERROR(ENOSYS);
    return s->oformat->control_message(s, type, data, data_size);
}

int avdevice_dev_to_app_control_message(struct AVFormatContext *s, enum AVDevToAppMessageType type,
                                        void *data, size_t data_size)
{
    if (!s->control_message_cb)
        return AVERROR(ENOSYS);
    return s->control_message_cb(s, type, data, data_size);
}

#if FF_API_DEVICE_CAPABILITIES
int avdevice_capabilities_create(AVDeviceCapabilitiesQuery **caps, AVFormatContext *s,
                                 AVDictionary **device_options)
{
    return AVERROR(ENOSYS);
}

void avdevice_capabilities_free(AVDeviceCapabilitiesQuery **caps, AVFormatContext *s)
{
    return;
}
#endif

int avdevice_list_devices(AVFormatContext *s, AVDeviceInfoList **device_list)
{
    int ret;
    av_assert0(s);
    av_assert0(device_list);
    av_assert0(s->oformat || s->iformat);
    if ((s->oformat && !s->oformat->get_device_list) ||
        (s->iformat && !s->iformat->get_device_list)) {
        *device_list = NULL;
        return AVERROR(ENOSYS);
    }
    *device_list = av_mallocz(sizeof(AVDeviceInfoList));
    if (!(*device_list))
        return AVERROR(ENOMEM);
    /* no default device by default */
    (*device_list)->default_device = -1;
    if (s->oformat)
        ret = s->oformat->get_device_list(s, *device_list);
    else
        ret = s->iformat->get_device_list(s, *device_list);
    if (ret < 0)
        avdevice_free_list_devices(device_list);
    return ret;
}

static int list_devices_for_context(AVFormatContext *s, AVDictionary *options,
                                    AVDeviceInfoList **device_list)
{
    AVDictionary *tmp = NULL;
    int ret;

    av_dict_copy(&tmp, options, 0);
    if ((ret = av_opt_set_dict2(s, &tmp, AV_OPT_SEARCH_CHILDREN)) < 0)
        goto fail;
    ret = avdevice_list_devices(s, device_list);
  fail:
    av_dict_free(&tmp);
    avformat_free_context(s);
    return ret;
}

int avdevice_list_input_sources(AVInputFormat *device, const char *device_name,
                                AVDictionary *device_options, AVDeviceInfoList **device_list)
{
    AVFormatContext *s = NULL;
    int ret;

    if ((ret = ff_alloc_input_device_context(&s, device, device_name)) < 0)
        return ret;
    return list_devices_for_context(s, device_options, device_list);
}

int avdevice_list_output_sinks(AVOutputFormat *device, const char *device_name,
                               AVDictionary *device_options, AVDeviceInfoList **device_list)
{
    AVFormatContext *s = NULL;
    int ret;

    if ((ret = avformat_alloc_output_context2(&s, device, device_name, NULL)) < 0)
        return ret;
    return list_devices_for_context(s, device_options, device_list);
}

void avdevice_free_list_devices(AVDeviceInfoList **device_list)
{
    AVDeviceInfoList *list;
    AVDeviceInfo *dev;
    int i;

    av_assert0(device_list);
    list = *device_list;
    if (!list)
        return;

    for (i = 0; i < list->nb_devices; i++) {
        dev = list->devices[i];
        if (dev) {
            av_freep(&dev->device_name);
            av_freep(&dev->device_description);
            av_free(dev);
        }
    }
    av_freep(&list->devices);
    av_freep(device_list);
}

#if CONFIG_LIBXMA2API
static void xlnx_init(int xlnx_num_devs, XmaXclbinParameter *xclbin_nparam )
{
    int i = 0;
    for(i=0; i< xlnx_num_devs;i++)
    {
        av_log (NULL, AV_LOG_INFO, "------------------i=%d------------------------------------------\n\n",i);
        av_log (NULL, AV_LOG_INFO, "   xclbin_name :  %s\n", xclbin_nparam[i].xclbin_name);
        av_log (NULL, AV_LOG_INFO, "   device_id   :  %d \n", xclbin_nparam[i].device_id);
        av_log (NULL, AV_LOG_INFO, "------------------------------------------------------------\n\n");
    }

    av_log(NULL, AV_LOG_ERROR, "---------> xma_initialize\n");
    /* Initialize the Xilinx Media Accelerator */
    if (xma_initialize(xclbin_nparam, xlnx_num_devs) != 0)
    {
        av_log(NULL, AV_LOG_ERROR, "ERROR: XMA Initialization failed. Program exiting\n");
    }
}

int avdevice_xlnx_hwdev_init(XmaXclbinParameter* xclbin_nparam, int xlnx_num_devs, int dev_id)
{
    av_log(NULL, AV_LOG_ERROR, "---------> 1\n");
    if (xlnx_num_devs == 0)
    {
        av_log(NULL, AV_LOG_ERROR, "---------> 2\n");
        if ((!getenv("XRM_DEVICE_ID")) && (!getenv("XRM_RESERVE_ID")))//TODO:check if this additional condition is needed
        {
            av_log(NULL, AV_LOG_ERROR, "---------> 3\n");
            setenv("XRM_DEVICE_ID", "0" , 0); //set defualt device to 0
            xclbin_nparam[xlnx_num_devs].device_id = dev_id;
            xclbin_nparam[xlnx_num_devs].xclbin_name = XLNX_XCLBIN_PATH;
            xlnx_num_devs++;
            av_log(NULL, AV_LOG_WARNING, "No device set hence falling to default device 0\n");
        }
    }
    else if (xlnx_num_devs > MAX_XLNX_DEVICES_PER_CMD)
    {
        av_log(NULL, AV_LOG_ERROR, "ERROR: ffmpeg command is requesting for  %d devices which is more than supported %d devices.\n", xlnx_num_devs, MAX_XLNX_DEVICES_PER_CMD);
        return AVERROR(EINVAL);
    }

    if (!getenv("XRM_RESERVE_ID"))
    {
        xlnx_init(xlnx_num_devs, xclbin_nparam );
    }

    return 0;
}
#endif
