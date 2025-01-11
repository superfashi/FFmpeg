/*
 * MPEG Media Transport Protocol (MMTP) parser, as defined in ISO/IEC 23008-1.
 * Copyright (c) 2025 SuperFashi
 *
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

#include <stdbool.h>

#include "libavcodec/bytestream.h"
#include "libavcodec/avcodec.h"
#include "libavutil/avassert.h"
#include "libavutil/mem.h"
#include "demux.h"
#include "internal.h"
#include "mmtp.h"
#include "network.h"

struct MMTGeneralLocationInfo {
    uint8_t location_type;
    union {
        struct {
            uint16_t packet_id;
        } type0;
        struct {
            struct in_addr ipv4_src_addr;
            struct in_addr ipv4_dst_addr;
            uint16_t       dst_port;
            uint16_t       packet_id;
        } type1;
        struct {
            struct in6_addr ipv6_src_addr;
            struct in6_addr ipv6_dst_addr;
            uint16_t        dst_port;
            uint16_t        packet_id;
        } type2;
        struct {
            uint16_t network_id;
            uint16_t MPEG_2_transport_stream_id;
            uint16_t MPEG_2_PID: 13;
        } type3;
        struct {
            struct in6_addr ipv6_src_addr;
            struct in6_addr ipv6_dst_addr;
            uint16_t        dst_port;
            uint16_t        MPEG_2_PID: 13;
        } type4;
        struct {
            char URL[0x100 + 1];
        } type5;
    };
};

static int parse_mmt_general_location_info(
    struct MMTGeneralLocationInfo *info, GetByteContext *gbc)
{
    uint8_t url_size;

    if (bytestream2_get_bytes_left(gbc) < 1)
        return AVERROR_INVALIDDATA;
    switch (info->location_type = bytestream2_get_byteu(gbc)) {
    case 0x00:
        if (bytestream2_get_bytes_left(gbc) < 2)
            return AVERROR_INVALIDDATA;
        info->type0.packet_id = bytestream2_get_be16u(gbc);
        break;
    case 0x01:
        if (bytestream2_get_bytes_left(gbc) < (32 + 32 + 16 + 16) / 8)
            return AVERROR_INVALIDDATA;
        bytestream2_get_bufferu(gbc, (uint8_t *) &info->type1.ipv4_src_addr, 4);
        bytestream2_get_bufferu(gbc, (uint8_t *) &info->type1.ipv4_dst_addr, 4);
        info->type1.dst_port  = bytestream2_get_be16u(gbc);
        info->type1.packet_id = bytestream2_get_be16u(gbc);
        break;
    case 0x02:
        if (bytestream2_get_bytes_left(gbc) < (128 + 128 + 16 + 16) / 8)
            return AVERROR_INVALIDDATA;
        bytestream2_get_bufferu(
            gbc, (uint8_t *) &info->type2.ipv6_src_addr, 16);
        bytestream2_get_bufferu(
            gbc, (uint8_t *) &info->type2.ipv6_dst_addr, 16);
        info->type2.dst_port  = bytestream2_get_be16u(gbc);
        info->type2.packet_id = bytestream2_get_be16u(gbc);
        break;
    case 0x03:
        if (bytestream2_get_bytes_left(gbc) < (16 + 16 + 3 + 13) / 8)
            return AVERROR_INVALIDDATA;
        info->type3.network_id                 = bytestream2_get_be16u(gbc);
        info->type3.MPEG_2_transport_stream_id = bytestream2_get_be16u(gbc);
        info->type3.MPEG_2_PID =
            bytestream2_get_be16u(gbc) & 0b1111111111111;
        break;
    case 0x04:
        if (bytestream2_get_bytes_left(gbc) < (128 + 128 + 16 + 3 + 13) / 8)
            return AVERROR_INVALIDDATA;
        bytestream2_get_bufferu(
            gbc, (uint8_t *) &info->type4.ipv6_src_addr, 16);
        bytestream2_get_bufferu(
            gbc, (uint8_t *) &info->type4.ipv6_dst_addr, 16);
        info->type4.dst_port   = bytestream2_get_be16u(gbc);
        info->type4.MPEG_2_PID = bytestream2_get_be16u(gbc) & 0b1111111111111;
        break;
    case 0x05:
        url_size = bytestream2_get_byte(gbc);
        bytestream2_get_buffer(gbc, (uint8_t *) info->type5.URL, url_size);
        info->type5.URL[url_size] = '\0';
        break;
    default:
        return AVERROR_INVALIDDATA;
    }
    return 0;
}

struct Streams {
    AVStream *stream;

    AVCodecParserContext *parser;

    int num_timestamp_descriptors;
    struct MPUTimestampDescriptor {
        uint32_t seq_num;
        int64_t  presentation_time;
    }   *timestamp_descriptor;

    int num_ext_timestamp_descriptors;
    struct MPUExtendedTimestampDescriptor {
        uint32_t seq_num;
        uint16_t decoding_time_offset;
        uint8_t  num_of_au;
        struct {
            uint16_t dts_pts_offset;
            uint16_t pts_offset;
        }        au[0x100];
    }   *ext_timestamp_descriptor;

    uint32_t last_sequence_number;
    uint16_t au_count;
    int64_t  offset;
    int      flags;

    struct Streams *next;
};

struct MMTPContext {
    struct FragmentAssembler *assembler;
    struct Streams           *streams;
    AVProgram                *program;
    // struct MMTGeneralLocationInfo mpt_location; TODO

    // below are temporary fields available for the scope of a single packet
    AVFormatContext *s;
    AVPacket        *pkt;
    uint16_t        current_pid;
    uint8_t         is_rap;
};

static struct Streams *find_current_stream(struct MMTPContext *ctx)
{
    struct Streams *streams;
    for (streams = ctx->streams; streams != NULL; streams = streams->next)
        if (streams->stream->id == ctx->current_pid)
            return streams;
    return NULL;
}

static struct Streams *
find_or_allocate_stream(struct MMTPContext *ctx, uint16_t pid)
{
    AVStream       *stream;
    struct Streams *streams;
    for (streams = ctx->streams; streams != NULL; streams = streams->next)
        if (streams->stream->id == pid)
            return streams;

    stream = avformat_new_stream(ctx->s, NULL);
    if (stream == NULL) return NULL;
    stream->id = pid;
    av_program_add_stream_index(ctx->s, ctx->program->id, stream->index);

    streams = av_mallocz(sizeof(struct Streams));
    if (streams == NULL) return NULL;
    streams->stream = stream;
    streams->next   = ctx->streams;
    streams->offset = -1;
    ctx->streams    = streams;
    return streams;
}

enum {
    MMT_PACKAGE_TABLE_ID  = 0x20,
    PACKAGE_LIST_TABLE_ID = 0x80,
    MH_EIT_TABLE_ID       = 0x8B,
};

enum {
    MPU_TIMESTAMP_DESCRIPTOR          = 0x0001,
    VIDEO_COMPONENT_DESCRIPTOR        = 0x8010,
    MH_STREAM_IDENTIFIER_DESCRIPTOR   = 0x8011,
    MH_AUDIO_COMPONENT_DESCRIPTOR     = 0x8014,
    MH_DATA_COMPONENT_DESCRIPTOR      = 0x8020,
    MPU_EXTENDED_TIMESTAMP_DESCRIPTOR = 0x8026,
    MH_SHORT_EVENT_DESCRIPTOR         = 0xF001,
};

static int
parse_video_component_descriptor(AVStream *stream, GetByteContext *gbc)
{
    uint8_t descriptor_length;
    uint8_t language_code[4];

    if (bytestream2_get_bytes_left(gbc) < (16 + 8) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_be16u(gbc) != VIDEO_COMPONENT_DESCRIPTOR)
        return AVERROR_INVALIDDATA;
    descriptor_length = bytestream2_get_byteu(gbc);

    if (bytestream2_get_bytes_left(gbc) < descriptor_length)
        return AVERROR_INVALIDDATA;
    {
        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, descriptor_length);
        /*
         * skip:
         * - video_resolution
         * - video_aspect_ratio
         * - video_scan_flag
         * - reserved
         * - video_frame_rate
         * - component_tag
         * - video_transfer_characteristics
         * - reserved
         */
        bytestream2_skip(&ngbc, (4 + 4 + 1 + 2 + 5 + 16 + 4 + 4) / 8);

        if (bytestream2_get_bytes_left(&ngbc) < 3)
            return AVERROR_INVALIDDATA;
        bytestream2_get_bufferu(&ngbc, language_code, 3);
        language_code[3] = '\0';
    }
    bytestream2_skipu(gbc, descriptor_length);

    if (stream == NULL) return 0;
    return av_dict_set(&stream->metadata, "language", language_code, 0);
}

static int
parse_mh_audio_component_descriptor(AVStream *stream, GetByteContext *gbc)
{
    uint8_t descriptor_length;
    uint8_t stream_content;
    uint8_t stream_type;
    uint8_t language_code[4];

    if (bytestream2_get_bytes_left(gbc) < (16 + 8) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_be16u(gbc) != MH_AUDIO_COMPONENT_DESCRIPTOR)
        return AVERROR_INVALIDDATA;
    descriptor_length = bytestream2_get_byteu(gbc);

    if (bytestream2_get_bytes_left(gbc) < descriptor_length)
        return AVERROR_INVALIDDATA;
    {
        uint8_t byte;
        bool ES_multi_lingual_flag;

        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, descriptor_length);

        if (bytestream2_get_bytes_left(&ngbc) <
            (4 + 4 + 8 + 16 + 8 + 8 + 1 + 1 + 2 + 3 + 1 + 24) / 8)
            return AVERROR_INVALIDDATA;

        byte           = bytestream2_get_byteu(&ngbc);
        stream_content = byte & 0b1111;

        /*
         * skip:
         * - component_type
         * - component_tag
         */
        bytestream2_skipu(&ngbc, 3);
        stream_type = bytestream2_get_byteu(&ngbc);

        // skip: simulcast_group_tag
        bytestream2_skipu(&ngbc, 1);

        byte                  = bytestream2_get_byteu(&ngbc);
        ES_multi_lingual_flag = byte >> 7;

        bytestream2_get_bufferu(&ngbc, language_code, 3);
        language_code[3] = '\0';

        if (ES_multi_lingual_flag) {
            if (bytestream2_get_bytes_left(&ngbc) < 3)
                return AVERROR_INVALIDDATA;
            bytestream2_skipu(&ngbc, 3);
        }
    }
    bytestream2_skipu(gbc, descriptor_length);

    if (stream == NULL) return 0;

    switch (stream_content) {
    case 0x3:
        switch (stream_type) {
        case 0x11:
            stream->codecpar->codec_id = AV_CODEC_ID_AAC_LATM;
            break;
        case 0x1c:
            stream->codecpar->codec_id = AV_CODEC_ID_AAC;
            break;
        }
        break;
    case 0x4:
        stream->codecpar->codec_id = AV_CODEC_ID_MP4ALS;
        break;
    }

    return av_dict_set(&stream->metadata, "language", language_code, 0);
}

#define MAX_NUM_TIMESTAMP_DESCRIPTOR 32
#define DIFF(a, b) ((a) > (b) ? ((a) - (b)) : ((b) - (a)))

static int
parse_mpu_timestamp_descriptor(struct Streams *streams, GetByteContext *gbc)
{
    uint8_t descriptor_length;

    if (bytestream2_get_bytes_left(gbc) < (16 + 8) / 8)
        return AVERROR_INVALIDDATA;

    if (bytestream2_get_be16u(gbc) != MPU_TIMESTAMP_DESCRIPTOR)
        return AVERROR_INVALIDDATA;
    descriptor_length = bytestream2_get_byteu(gbc);

    if (bytestream2_get_bytes_left(gbc) < descriptor_length)
        return AVERROR_INVALIDDATA;
    {
        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, descriptor_length);

        while (bytestream2_get_bytes_left(&ngbc) > 0) {
            uint64_t mpu_seq_num;
            int64_t  mpu_presentation_time;
            size_t   i;

            struct MPUTimestampDescriptor *desc;

            if (bytestream2_get_bytes_left(&ngbc) < (32 + 64) / 8)
                return AVERROR_INVALIDDATA;
            mpu_seq_num = bytestream2_get_be32u(&ngbc);
            mpu_presentation_time =
                ff_parse_ntp_time(bytestream2_get_be64u(&ngbc)) - NTP_OFFSET_US;

            if (mpu_seq_num >= streams->last_sequence_number) {
                for (i = 0; i < streams->num_timestamp_descriptors; ++i)
                    if (streams->timestamp_descriptor[i].seq_num ==
                        mpu_seq_num) {
                        desc = streams->timestamp_descriptor + i;
                        goto end2;
                    }

                for (i = 0; i < streams->num_timestamp_descriptors; ++i)
                    if (streams->timestamp_descriptor[i].seq_num <
                        streams->last_sequence_number) {
                        desc = streams->timestamp_descriptor + i;
                        goto end1;
                    }

                if (streams->num_timestamp_descriptors + 1 >
                    MAX_NUM_TIMESTAMP_DESCRIPTOR) {
                    // we have all descriptors larger than the current sequence number
                    // we can't add more, so we should evict the one with the largest distance
                    uint64_t max_dist = 0;
                    for (i = 0; i < streams->num_timestamp_descriptors; ++i)
                        if (DIFF(
                                streams->timestamp_descriptor[i].seq_num,
                                mpu_seq_num) > max_dist) {
                            desc     = streams->timestamp_descriptor + i;
                            max_dist = DIFF(
                                streams->timestamp_descriptor[i].seq_num,
                                mpu_seq_num);
                        }
                    av_assert1(desc != NULL); // should never fail
                    goto end1;
                }

                desc = av_dynarray2_add(
                    (void **) &streams->timestamp_descriptor,
                    &streams->num_timestamp_descriptors,
                    sizeof(struct MPUTimestampDescriptor), NULL);
                if (desc == NULL) return AVERROR(ENOMEM);

                end1:
                desc->seq_num           = mpu_seq_num;
                end2:
                desc->presentation_time = mpu_presentation_time;
            }
        }
    }
    bytestream2_skipu(gbc, descriptor_length);

    return 0;
}

static int parse_mpu_extended_timestamp_descriptor(
    struct Streams *streams, GetByteContext *gbc)
{
    uint8_t descriptor_length;

    AVStream *stream = streams->stream;

    if (bytestream2_get_bytes_left(gbc) < (16 + 8) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_be16u(gbc) != MPU_EXTENDED_TIMESTAMP_DESCRIPTOR)
        return AVERROR_INVALIDDATA;
    descriptor_length = bytestream2_get_byteu(gbc);

    if (bytestream2_get_bytes_left(gbc) < descriptor_length)
        return AVERROR_INVALIDDATA;
    {
        uint8_t  byte;
        uint8_t  pts_offset_type;
        bool timescale_flag;
        uint16_t default_pts_offset = 0;

        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, descriptor_length);

        if (bytestream2_get_bytes_left(&ngbc) < (5 + 2 + 1) / 8)
            return AVERROR_INVALIDDATA;
        byte            = bytestream2_get_byte(&ngbc);
        pts_offset_type = (byte >> 1) & 0b11;
        timescale_flag  = byte & 1;

        if (timescale_flag) {
            if (bytestream2_get_bytes_left(&ngbc) < 4)
                return AVERROR_INVALIDDATA;
            stream->time_base.num = 1;
            stream->time_base.den = bytestream2_get_be32u(&ngbc);
        }

        if (pts_offset_type == 1) {
            if (bytestream2_get_bytes_left(&ngbc) < 2)
                return AVERROR_INVALIDDATA;
            default_pts_offset = bytestream2_get_be16u(&ngbc);
        }

        while (bytestream2_get_bytes_left(&ngbc) > 0) {
            size_t   i;
            uint8_t  num_of_au;
            uint16_t decoding_time_offset;
            uint64_t mpu_seq_num;

            struct MPUExtendedTimestampDescriptor *desc = NULL;

            if (pts_offset_type == 0)
                return AVERROR_PATCHWELCOME;  // we don't know how to handle this

            if (bytestream2_get_bytes_left(&ngbc) < (32 + 2 + 6 + 16 + 8) / 8)
                return AVERROR_INVALIDDATA;
            mpu_seq_num = bytestream2_get_be32u(&ngbc);
            // skip: leap_indicator
            bytestream2_skip(&ngbc, (2 + 6) / 8);
            decoding_time_offset = bytestream2_get_be16u(&ngbc);
            num_of_au            = bytestream2_get_byteu(&ngbc);

            if (mpu_seq_num >= streams->last_sequence_number) {
                for (i = 0; i < streams->num_ext_timestamp_descriptors; ++i)
                    if (streams->ext_timestamp_descriptor[i].seq_num ==
                        mpu_seq_num) {
                        desc = streams->ext_timestamp_descriptor + i;
                        goto end2;
                    }

                for (i = 0; i < streams->num_ext_timestamp_descriptors; ++i)
                    if (streams->ext_timestamp_descriptor[i].seq_num <
                        streams->last_sequence_number) {
                        desc = streams->ext_timestamp_descriptor + i;
                        goto end1;
                    }

                if (streams->num_ext_timestamp_descriptors + 1 >
                    MAX_NUM_TIMESTAMP_DESCRIPTOR) {
                    uint64_t max_diff = 0;
                    for (i = 0; i < streams->num_ext_timestamp_descriptors; ++i)
                        if (DIFF(
                                streams->ext_timestamp_descriptor[i].seq_num,
                                mpu_seq_num) > max_diff) {
                            desc     = streams->ext_timestamp_descriptor + i;
                            max_diff = DIFF(
                                streams->ext_timestamp_descriptor[i].seq_num,
                                mpu_seq_num);
                        }
                    av_assert1(desc != NULL);
                    goto end1;
                }

                desc = av_dynarray2_add(
                    (void **) &streams->ext_timestamp_descriptor,
                    &streams->num_ext_timestamp_descriptors,
                    sizeof(struct MPUExtendedTimestampDescriptor), NULL);
                if (desc == NULL)
                    return AVERROR(ENOMEM);

                end1:
                desc->seq_num              = mpu_seq_num;
                end2:
                desc->decoding_time_offset = decoding_time_offset;
                desc->num_of_au            = num_of_au;
            }

            for (i = 0; i < num_of_au; ++i) {
                if (bytestream2_get_bytes_left(&ngbc) < 2)
                    return AVERROR_INVALIDDATA;
                if (desc != NULL)
                    desc->au[i].dts_pts_offset = bytestream2_get_be16u(&ngbc);
                else
                    bytestream2_skipu(&ngbc, 2);

                if (pts_offset_type == 2) {
                    if (bytestream2_get_bytes_left(&ngbc) < 2)
                        return AVERROR_INVALIDDATA;
                    if (desc != NULL)
                        desc->au[i].pts_offset = bytestream2_get_be16u(&ngbc);
                    else
                        bytestream2_skipu(&ngbc, 2);
                } else if (desc != NULL) {
                    desc->au[i].pts_offset = default_pts_offset;
                }
            }
        }
    }
    bytestream2_skipu(gbc, descriptor_length);

    return 0;
}

static int
parse_additional_arib_subtitle_info(AVStream *stream, GetByteContext *gbc)
{
    bool    start_mpu_sequence_number_flag;
    char    language_code[4];
    uint8_t subtitle_format;

    if (bytestream2_get_bytes_left(gbc) <
        (8 + 4 + 1 + 3 + 24 + 2 + 4 + 2 + 4 + 4 + 4 + 4) / 8)
        return AVERROR_INVALIDDATA;
    // skip: subtitle_tag
    bytestream2_skipu(gbc, 1);
    start_mpu_sequence_number_flag = (bytestream2_get_byteu(gbc) >> 3) & 1;
    bytestream2_get_bufferu(gbc, language_code, 3);
    language_code[3] = '\0';
    subtitle_format = (bytestream2_get_byteu(gbc) >> 2) & 0b1111;
    /*
     * skip:
     * - TMD
     * - DMF
     * - resolution
     * - compression_type
     */
    bytestream2_skipu(gbc, (4 + 4 + 4 + 4) / 8);

    if (start_mpu_sequence_number_flag)
        bytestream2_skip(gbc, 32);

    switch (subtitle_format) {
    case 0b0000:
        stream->codecpar->codec_id = AV_CODEC_ID_TTML;
        break;
    }

    return av_dict_set(&stream->metadata, "language", language_code, 0);
}

static int
parse_mh_data_component_descriptor(AVStream *stream, GetByteContext *gbc)
{
    uint8_t descriptor_length;

    if (bytestream2_get_bytes_left(gbc) < (16 + 8) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_be16u(gbc) != MH_DATA_COMPONENT_DESCRIPTOR)
        return AVERROR_INVALIDDATA;
    descriptor_length = bytestream2_get_byteu(gbc);

    if (bytestream2_get_bytes_left(gbc) < descriptor_length)
        return AVERROR_INVALIDDATA;
    {
        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, descriptor_length);
        bytestream2_skipu(gbc, descriptor_length);

        if (bytestream2_get_bytes_left(&ngbc) < 16 / 8)
            return AVERROR_INVALIDDATA;
        switch (bytestream2_get_be16u(&ngbc)) {
        case 0x0020: // additional ARIB subtitle info (Table 7-74, ARIB STD-B60, Version 1.14-E1)
            return parse_additional_arib_subtitle_info(stream, &ngbc);
        }
    }

    return 0;
}

static int
parse_stream_identifier_descriptor(AVStream *stream, GetByteContext *gbc)
{
    uint8_t descriptor_length;

    if (bytestream2_get_bytes_left(gbc) < (16 + 8) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_be16u(gbc) != MH_STREAM_IDENTIFIER_DESCRIPTOR)
        return AVERROR_INVALIDDATA;
    descriptor_length = bytestream2_get_byteu(gbc);

    if (bytestream2_get_bytes_left(gbc) < descriptor_length)
        return AVERROR_INVALIDDATA;
    {
        // no need for now
    }
    bytestream2_skipu(gbc, descriptor_length);

    return 0;
}

static int skip_unknown_descriptor(void *log, GetByteContext *gbc)
{
    // assumes at least 3 bytes left to read in gbc
    const uint16_t descriptor_tag = bytestream2_get_be16u(gbc);
    unsigned int   descriptor_length;

    av_log(log, AV_LOG_VERBOSE, "Unknown descriptor: 0x%04x\n", descriptor_tag);

    if (descriptor_tag <= 0x3FFF) {        // 8-bit length descriptor
        descriptor_length = bytestream2_get_byteu(gbc);
    } else if (descriptor_tag <= 0x6FFF) { // 16-bit length descriptor
        if (bytestream2_get_bytes_left(gbc) < 2)
            return AVERROR_INVALIDDATA;
        descriptor_length = bytestream2_get_be16u(gbc);
    } else if (descriptor_tag <= 0x7FFF) { // 32-bit length descriptor
        if (bytestream2_get_bytes_left(gbc) < 4)
            return AVERROR_INVALIDDATA;
        descriptor_length = bytestream2_get_be32u(gbc);
    } else if (descriptor_tag <= 0xEFFF) { // 8-bit length descriptor
        descriptor_length = bytestream2_get_byteu(gbc);
    } else {                               // 16-bit length descriptor
        if (bytestream2_get_bytes_left(gbc) < 2)
            return AVERROR_INVALIDDATA;
        descriptor_length = bytestream2_get_be16u(gbc);
    }

    if (bytestream2_get_bytes_left(gbc) < descriptor_length)
        return AVERROR_INVALIDDATA;
    bytestream2_skipu(gbc, descriptor_length);
    return 0;
}

static int parse_mpt_descriptor(struct Streams *streams, GetByteContext *gbc)
{
    if (bytestream2_get_bytes_left(gbc) < 3)
        return AVERROR_INVALIDDATA;
    switch (bytestream2_peek_be16u(gbc)) {
    case MPU_TIMESTAMP_DESCRIPTOR:
        return parse_mpu_timestamp_descriptor(streams, gbc);
    case VIDEO_COMPONENT_DESCRIPTOR:
        return parse_video_component_descriptor(streams->stream, gbc);
    case MH_STREAM_IDENTIFIER_DESCRIPTOR:
        return parse_stream_identifier_descriptor(streams->stream, gbc);
    case MH_AUDIO_COMPONENT_DESCRIPTOR:
        return parse_mh_audio_component_descriptor(streams->stream, gbc);
    case MH_DATA_COMPONENT_DESCRIPTOR:
        return parse_mh_data_component_descriptor(streams->stream, gbc);
    case MPU_EXTENDED_TIMESTAMP_DESCRIPTOR:
        return parse_mpu_extended_timestamp_descriptor(streams, gbc);
    default:
        return skip_unknown_descriptor(streams->stream, gbc);
    }
}

static int parse_mh_short_event_descriptor(
    MMTPContext *ctx, GetByteContext *gbc)
{
    uint16_t descriptor_length;

    if (bytestream2_get_bytes_left(gbc) < (16 + 16) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_be16u(gbc) != MH_SHORT_EVENT_DESCRIPTOR)
        return AVERROR_INVALIDDATA;
    descriptor_length = bytestream2_get_be16u(gbc);

    if (bytestream2_get_bytes_left(gbc) < descriptor_length)
        return AVERROR_INVALIDDATA;
    {
        uint8_t  language_code[4];
        uint8_t  event_name_length;
        uint16_t text_length;
        char     *event_name, *text;

        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, descriptor_length);

        bytestream2_get_buffer(&ngbc, language_code, 3);
        language_code[3] = '\0';

        event_name_length = bytestream2_get_byte(&ngbc);
        if (bytestream2_get_bytes_left(&ngbc) < event_name_length)
            return AVERROR_INVALIDDATA;
        event_name = av_strndup(ngbc.buffer, event_name_length);
        bytestream2_skipu(&ngbc, event_name_length);

        av_dict_set(&ctx->program->metadata, "language", language_code, 0);
        av_dict_set(&ctx->program->metadata, "title", event_name,
                    AV_DICT_DONT_STRDUP_VAL);

        text_length = bytestream2_get_be16u(&ngbc);
        if (bytestream2_get_bytes_left(&ngbc) < text_length)
            return AVERROR_INVALIDDATA;
        text = av_strndup(ngbc.buffer, text_length);
        bytestream2_skipu(&ngbc, text_length);

        av_dict_set(&ctx->program->metadata, "description", text,
                    AV_DICT_DONT_STRDUP_VAL);
    }
    bytestream2_skipu(gbc, descriptor_length);

    return 0;
}

static int parse_mh_eit_descriptor(MMTPContext *ctx, GetByteContext *gbc)
{
    if (bytestream2_get_bytes_left(gbc) < 3)
        return AVERROR_INVALIDDATA;
    switch (bytestream2_peek_be16u(gbc)) {
    case VIDEO_COMPONENT_DESCRIPTOR:
        return parse_video_component_descriptor(NULL, gbc);
    case MH_AUDIO_COMPONENT_DESCRIPTOR:
        return parse_mh_audio_component_descriptor(NULL, gbc);
    case MH_SHORT_EVENT_DESCRIPTOR:
        return parse_mh_short_event_descriptor(ctx, gbc);
    default:
        return skip_unknown_descriptor(ctx->s, gbc);
    }
}

static int parse_mmt_package_table(MMTPContext *ctx, GetByteContext *gbc)
{
    uint16_t length;

    if (bytestream2_get_bytes_left(gbc) < (8 + 8 + 16) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_byteu(gbc) != MMT_PACKAGE_TABLE_ID)
        return AVERROR_INVALIDDATA;
    // skip: version
    bytestream2_skipu(gbc, 1);
    length = bytestream2_get_be16u(gbc);

    if (bytestream2_get_bytes_left(gbc) < length)
        return AVERROR_INVALIDDATA;
    {
        size_t   i, j;
        uint8_t  package_id_length;
        uint16_t descriptors_length;
        uint8_t  number_of_assets;

        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, length);

        if (bytestream2_get_bytes_left(&ngbc) < (6 + 2 + 8) / 8)
            return AVERROR_INVALIDDATA;

        // skip: MPT_mode
        bytestream2_skipu(&ngbc, 1);
        package_id_length = bytestream2_get_byteu(&ngbc);

        bytestream2_skip(&ngbc, package_id_length);

        descriptors_length = bytestream2_get_be16(&ngbc);
        bytestream2_skip(&ngbc, descriptors_length);

        if (bytestream2_get_bytes_left(&ngbc) < 1)
            return AVERROR_INVALIDDATA;
        number_of_assets = bytestream2_get_byteu(&ngbc);

        for (i = 0; i < number_of_assets; ++i) {
            int err;

            uint8_t  asset_id_length;
            uint8_t  location_count;
            uint16_t asset_descriptors_length;
            uint32_t asset_type;

            struct Streams *stream = NULL;

            struct MMTGeneralLocationInfo info;

            if (bytestream2_get_bytes_left(&ngbc) < (8 + 32 + 8) / 8)
                return AVERROR_INVALIDDATA;
            /*
             * skip:
             * - identifier_type
             * - asset_id_scheme
             */
            bytestream2_skipu(&ngbc, (8 + 32) / 8);
            asset_id_length = bytestream2_get_byteu(&ngbc);

            bytestream2_skip(&ngbc, asset_id_length);

            asset_type = bytestream2_get_le32(&ngbc);

            // skip: asset_clock_relation_flag
            bytestream2_skip(&ngbc, 1);

            if (bytestream2_get_bytes_left(&ngbc) < 1)
                return AVERROR_INVALIDDATA;
            location_count = bytestream2_get_byteu(&ngbc);

            for (j = 0; j < location_count; ++j)
                if ((err = parse_mmt_general_location_info(&info, &ngbc)) < 0)
                    return err;

            switch (asset_type) {
            case MKTAG('h', 'e', 'v', '1'):
                if (info.location_type != 0x00) return AVERROR_PATCHWELCOME;
                stream = find_or_allocate_stream(ctx, info.type0.packet_id);
                if (stream == NULL) return AVERROR(ENOMEM);
                stream->stream->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
                stream->stream->codecpar->codec_id   = AV_CODEC_ID_HEVC;
                stream->stream->codecpar->codec_tag  = asset_type;
                break;
            case MKTAG('m', 'p', '4', 'a'):
                if (info.location_type != 0x00) return AVERROR_PATCHWELCOME;
                stream = find_or_allocate_stream(ctx, info.type0.packet_id);
                if (stream == NULL) return AVERROR(ENOMEM);
                stream->stream->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
                stream->stream->codecpar->codec_tag  = asset_type;
                break;
            case MKTAG('s', 't', 'p', 'p'):
                if (info.location_type == 0x00) {
                    stream = find_or_allocate_stream(ctx, info.type0.packet_id);
                    if (stream == NULL) return AVERROR(ENOMEM);
                    stream->stream->codecpar->codec_type = AVMEDIA_TYPE_SUBTITLE;
                    stream->stream->codecpar->codec_tag  = asset_type;
                }
                break;
            case MKTAG('a', 'a', 'p', 'p'):
            case MKTAG('a', 's', 'g', 'd'):
            case MKTAG('a', 'a', 'g', 'd'):
                break; // TODO
            }

            if (bytestream2_get_bytes_left(&ngbc) < 2)
                return AVERROR_INVALIDDATA;
            asset_descriptors_length = bytestream2_get_be16u(&ngbc);
            if (bytestream2_get_bytes_left(&ngbc) < asset_descriptors_length)
                return AVERROR_INVALIDDATA;
            if (stream != NULL) {
                GetByteContext nngbc;
                bytestream2_init(&nngbc, ngbc.buffer, asset_descriptors_length);

                while (bytestream2_get_bytes_left(&nngbc) > 0)
                    if ((err = parse_mpt_descriptor(stream, &nngbc)) < 0)
                        return err;
            }
            bytestream2_skipu(&ngbc, asset_descriptors_length);
        }
    }
    bytestream2_skipu(gbc, length);

    return 0;
}

static int parse_package_list_table(MMTPContext *ctx, GetByteContext *gbc)
{
    size_t   i;
    uint32_t length;

    if (bytestream2_get_bytes_left(gbc) < (8 + 8 + 16) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_byteu(gbc) != PACKAGE_LIST_TABLE_ID)
        return AVERROR_INVALIDDATA;
    // skip: version
    bytestream2_skipu(gbc, 1);
    length = bytestream2_get_be16u(gbc);

    if (bytestream2_get_bytes_left(gbc) < length)
        return AVERROR_INVALIDDATA;
    {
        int     err;
        uint8_t num_of_package;
        uint8_t num_of_ip_delivery;

        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, length);

        if (bytestream2_get_bytes_left(gbc) < 1)
            return AVERROR_INVALIDDATA;
        num_of_package = bytestream2_get_byteu(&ngbc);

        for (i = 0; i < num_of_package; ++i) {
            uint8_t                       package_id_length;
            struct MMTGeneralLocationInfo info;

            package_id_length = bytestream2_get_byte(&ngbc);
            bytestream2_skip(&ngbc, package_id_length);

            if ((err = parse_mmt_general_location_info(&info, &ngbc)) < 0)
                return err;
        }

        if (bytestream2_get_bytes_left(&ngbc) < 1)
            return AVERROR_INVALIDDATA;
        num_of_ip_delivery = bytestream2_get_byteu(&ngbc);

        for (i = 0; i < num_of_ip_delivery; ++i)
            return AVERROR_PATCHWELCOME;
    }
    bytestream2_skipu(gbc, length);

    return 0;
}

static int parse_mh_eit_table(MMTPContext *ctx, GetByteContext *gbc)
{
    uint16_t section_length;

    if (bytestream2_get_bytes_left(gbc) < (8 + 1 + 1 + 2 + 12) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_byteu(gbc) != MH_EIT_TABLE_ID)
        return AVERROR_INVALIDDATA;
    section_length = bytestream2_get_be16u(gbc) & 0b0000111111111111;

    if (bytestream2_get_bytes_left(gbc) < section_length || section_length < 4)
        return AVERROR_INVALIDDATA;
    {
        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, section_length - 4);

        bytestream2_skip(&ngbc, (16 + 2 + 5 + 1 + 8 + 8 + 16 + 16 + 8 + 8) / 8);

        while (bytestream2_get_bytes_left(&ngbc) > 0) {
            uint16_t descriptors_loop_length;

            bytestream2_skip(&ngbc, (16 + 40 + 24) / 8);
            descriptors_loop_length =
                bytestream2_get_be16u(&ngbc) & 0b0000111111111111;

            if (bytestream2_get_bytes_left(&ngbc) < descriptors_loop_length)
                return AVERROR_INVALIDDATA;
            {
                int            err;
                GetByteContext nngbc;
                bytestream2_init(&nngbc, ngbc.buffer, descriptors_loop_length);

                while (bytestream2_get_bytes_left(&nngbc) > 0)
                    if ((err = parse_mh_eit_descriptor(ctx, &nngbc)) < 0)
                        return err;
            }
            bytestream2_skipu(&ngbc, descriptors_loop_length);
        }
    }
    bytestream2_skipu(gbc, section_length);

    return 0;
}

static int parse_table(MMTPContext *ctx, GetByteContext *gbc)
{
    if (bytestream2_get_bytes_left(gbc) < 2)
        return AVERROR_INVALIDDATA;
    switch (bytestream2_peek_byteu(gbc)) {
    case MMT_PACKAGE_TABLE_ID:
        return parse_mmt_package_table(ctx, gbc);
    case PACKAGE_LIST_TABLE_ID:
        return parse_package_list_table(ctx, gbc);
    case MH_EIT_TABLE_ID:
        return parse_mh_eit_table(ctx, gbc);
    }
    bytestream2_skipu(gbc, bytestream2_get_bytes_left(gbc)); // TODO
    return 0;
}

enum {
    PA_MESSAGE_ID      = 0x0000,
    M2_SECTION_MESSAGE = 0x8000,
};

static int parse_pa_message(MMTPContext *ctx, GetByteContext *gbc)
{
    uint32_t length;

    if (bytestream2_get_bytes_left(gbc) < (16 + 8 + 32) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_be16u(gbc) != PA_MESSAGE_ID)
        return AVERROR_INVALIDDATA;
    // skip: version
    bytestream2_skipu(gbc, 1);
    length = bytestream2_get_be32u(gbc);

    if (bytestream2_get_bytes_left(gbc) < length)
        return AVERROR_INVALIDDATA;
    {
        size_t  i;
        uint8_t num_of_tables;

        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, length);

        if (bytestream2_get_bytes_left(gbc) < 1)
            return AVERROR_INVALIDDATA;
        num_of_tables = bytestream2_get_byteu(&ngbc);

        for (i = 0; i < num_of_tables; ++i) {
            bytestream2_skip(&ngbc, (8 + 8 + 16) / 8);
        }

        while (bytestream2_get_bytes_left(&ngbc) > 0) {
            int err = parse_table(ctx, &ngbc);
            if (err < 0) return err;
        }
    }
    bytestream2_skipu(gbc, length);

    return 0;
}

static int parse_m2_section_message(MMTPContext *ctx, GetByteContext *gbc)
{
    int      err;
    uint16_t length;

    if (bytestream2_get_bytes_left(gbc) < (16 + 8 + 16) / 8)
        return AVERROR_INVALIDDATA;
    if (bytestream2_get_be16u(gbc) != M2_SECTION_MESSAGE)
        return AVERROR_INVALIDDATA;
    // skip: version
    bytestream2_skipu(gbc, 1);
    length = bytestream2_get_be16u(gbc);

    if (bytestream2_get_bytes_left(gbc) < length)
        return AVERROR_INVALIDDATA;
    {
        GetByteContext ngbc;
        bytestream2_init(&ngbc, gbc->buffer, length);
        err = parse_table(ctx, &ngbc);
    }
    bytestream2_skipu(gbc, length);

    return err;
}

static int parse_signalling_message(MMTPContext *ctx, GetByteContext *gbc)
{
    if (bytestream2_get_bytes_left(gbc) < 4)
        return AVERROR_INVALIDDATA;
    switch (bytestream2_peek_be16u(gbc)) {
    case PA_MESSAGE_ID:
        return parse_pa_message(ctx, gbc);
    case M2_SECTION_MESSAGE:
        return parse_m2_section_message(ctx, gbc);
    }
    return 0;
}

enum FragmentationIndicator {
    NOT_FRAGMENTED  = 0b00,
    FIRST_FRAGMENT  = 0b01,
    MIDDLE_FRAGMENT = 0b10,
    LAST_FRAGMENT   = 0b11,
};

struct FragmentAssembler {
    uint16_t                 pid;
    struct FragmentAssembler *next;

    uint8_t *data;
    size_t  size, cap;

    uint32_t last_seq;

    enum {
        INIT = 0,
        NOT_STARTED,
        IN_FRAGMENT,
        SKIP,
    }        state;
};

static int
append_data(struct FragmentAssembler *ctx, const uint8_t *data, uint32_t size)
{
    if (ctx->size + size > UINT32_MAX) return AVERROR(EOVERFLOW);
    if (ctx->cap < ctx->size + size) {
        void   *new_data;
        size_t new_cap = ctx->cap == 0 ? 1024 : ctx->cap * 2;
        while (new_cap < ctx->size + size) new_cap *= 2;

        new_data = av_realloc(ctx->data, new_cap);
        if (new_data == NULL) return AVERROR(errno);
        ctx->data = new_data;
        ctx->cap  = new_cap;
    }
    memcpy(ctx->data + ctx->size, data, size);
    ctx->size += size;
    return 0;
}

static void
check_state(MMTPContext *ctx, struct FragmentAssembler *ass, uint32_t seq_num)
{
    if (ass->state == INIT) {
        ass->state = SKIP;
    } else if (seq_num != ass->last_seq + 1) {
        if (ass->size != 0) {
            av_log(ctx->s, AV_LOG_WARNING,
                   "Packet sequence number jump: %u + 1 != %u, drop %zu bytes\n",
                   ass->last_seq, seq_num, ass->size);
            ass->size = 0;
        } else {
            av_log(ctx->s, AV_LOG_WARNING,
                   "Packet sequence number jump: %u + 1 != %u\n",
                   ass->last_seq, seq_num);
        }
        ass->state = SKIP;
    }
    ass->last_seq = seq_num;
}

static int assemble_fragment(
    struct FragmentAssembler *ctx, uint32_t seq_num,
    enum FragmentationIndicator indicator,
    const uint8_t *data, uint32_t size,
    int (*parser)(MMTPContext *, GetByteContext *),
    MMTPContext *opaque)
{
    GetByteContext gbc;
    int            err;

    switch (indicator) {
    case NOT_FRAGMENTED:
        if (ctx->state == IN_FRAGMENT) return AVERROR_INVALIDDATA;
        ctx->state = NOT_STARTED;
        bytestream2_init(&gbc, data, size);
        return parser(opaque, &gbc);
    case FIRST_FRAGMENT:
        if (ctx->state == IN_FRAGMENT) return AVERROR_INVALIDDATA;
        ctx->state = IN_FRAGMENT;
        return append_data(ctx, data, size);
    case MIDDLE_FRAGMENT:
        if (ctx->state == SKIP) {
            av_log(opaque->s, AV_LOG_VERBOSE, "Drop packet %u\n", seq_num);
            return 0;
        }
        if (ctx->state != IN_FRAGMENT) return AVERROR_INVALIDDATA;
        return append_data(ctx, data, size);
    case LAST_FRAGMENT:
        if (ctx->state == SKIP) {
            av_log(opaque->s, AV_LOG_VERBOSE, "Drop packet %u\n", seq_num);
            return 0;
        }
        if (ctx->state != IN_FRAGMENT) return AVERROR_INVALIDDATA;
        if ((err = append_data(ctx, data, size)) < 0) return err;

        bytestream2_init(&gbc, ctx->data, ctx->size);
        err = parser(opaque, &gbc);

        ctx->size  = 0;
        ctx->state = NOT_STARTED;
        return err;
    default:
        return AVERROR_INVALIDDATA;
    }
}

static struct FragmentAssembler *
find_or_allocate_assembler(MMTPContext *ctx, uint16_t pid)
{
    struct FragmentAssembler *ass;
    for (ass = ctx->assembler; ass != NULL; ass = ass->next)
        if (ass->pid == pid)
            return ass;

    ass = av_mallocz(sizeof(struct FragmentAssembler));
    if (ass == NULL) return NULL;
    ass->pid              = pid;
    ass->next             = ctx->assembler;
    return ctx->assembler = ass;
}

static int parse_signalling_messages(
    MMTPContext *ctx, uint32_t seq_num, GetByteContext *gbc)
{
    int                         err;
    uint8_t                     byte;
    enum FragmentationIndicator fragmentation_indicator;
    bool                        length_extension_flag;
    bool                        aggregation_flag;

    struct FragmentAssembler *assembler = find_or_allocate_assembler(
        ctx, ctx->current_pid);
    if (assembler == NULL) return AVERROR(errno);

    if (bytestream2_get_bytes_left(gbc) < (2 + 4 + 1 + 1 + 8) / 8)
        return AVERROR_INVALIDDATA;
    byte                    = bytestream2_get_byteu(gbc);
    fragmentation_indicator = byte >> 6;
    length_extension_flag   = (byte >> 1) & 1;
    aggregation_flag        = byte & 1;

    bytestream2_skipu(gbc, 1);

    check_state(ctx, assembler, seq_num);

    if (!aggregation_flag)
        return assemble_fragment(
            assembler, seq_num, fragmentation_indicator,
            gbc->buffer, bytestream2_get_bytes_left(gbc),
            parse_signalling_message, ctx);

    if (fragmentation_indicator != NOT_FRAGMENTED)
        return AVERROR_INVALIDDATA; // cannot be both fragmented and aggregated

    while (bytestream2_get_bytes_left(gbc) > 0) {
        uint32_t length;

        if (length_extension_flag)
            length = bytestream2_get_be32(gbc);
        else
            length = bytestream2_get_be16(gbc);

        if (bytestream2_get_bytes_left(gbc) < length)
            return AVERROR_INVALIDDATA;
        if ((err = assemble_fragment(
            assembler, seq_num, NOT_FRAGMENTED,
            gbc->buffer, length, parse_signalling_message, ctx)) < 0)
            return err;
        bytestream2_skipu(gbc, length);
    }

    return 0;
}

static int fill_pts_dts(struct Streams *s)
{
    struct MPUTimestampDescriptor         *desc     = NULL;
    struct MPUExtendedTimestampDescriptor *ext_desc = NULL;

    int64_t ptime;
    size_t  i, j;

    for (i = 0; i < s->num_timestamp_descriptors; ++i) {
        if (s->timestamp_descriptor[i].seq_num ==
            s->last_sequence_number) {
            desc = s->timestamp_descriptor + i;
            break;
        }
    }

    for (i = 0; i < s->num_ext_timestamp_descriptors; ++i) {
        if (s->ext_timestamp_descriptor[i].seq_num ==
            s->last_sequence_number) {
            ext_desc = s->ext_timestamp_descriptor + i;
            break;
        }
    }

    if (desc == NULL || ext_desc == NULL) return FFERROR_REDO;
    ptime = av_rescale(desc->presentation_time, s->stream->time_base.den,
                       1000000ll * s->stream->time_base.num);

    if (s->au_count >= ext_desc->num_of_au)
        return AVERROR_INVALIDDATA;

    s->parser->dts = ptime - ext_desc->decoding_time_offset;

    for (j = 0; j < s->au_count; ++j)
        s->parser->dts += ext_desc->au[j].pts_offset;

    s->parser->pts = s->parser->dts + ext_desc->au[s->au_count].dts_pts_offset;

    ++s->au_count;
    return 0;
}

static int emit_closed_caption_mfu(MMTPContext *ctx, struct Streams *st,
                                   GetByteContext *gbc)
{
    uint8_t  data_type, subsample_number, last_subsample_number, byte;
    uint32_t data_size;
    size_t   i;
    int      err;
    bool     length_ext_flag, subsample_info_list_flag;

    av_assert0(ctx->pkt != NULL);

    if (bytestream2_get_bytes_left(gbc) < (8 + 8 + 8 + 8 + 4 + 1 + 1 + 2) / 8)
        return AVERROR_INVALIDDATA;

    /*
     * skip:
     * - subtitle_tag
     * - subtitle_sequence_number
     */
    bytestream2_skipu(gbc, (8 + 8) / 8);

    subsample_number      = bytestream2_get_byteu(gbc);
    last_subsample_number = bytestream2_get_byteu(gbc);

    byte                     = bytestream2_get_byteu(gbc);
    data_type                = byte >> 4;
    length_ext_flag          = (byte >> 3) & 1;
    subsample_info_list_flag = (byte >> 2) & 1;

    if (data_type != 0b0000) return AVERROR_PATCHWELCOME;

    if (length_ext_flag)
        data_size = bytestream2_get_be32(gbc);
    else
        data_size = bytestream2_get_be16(gbc);

    if (subsample_number == 0 && last_subsample_number > 0 &&
        subsample_info_list_flag) {
        for (i = 0; i < last_subsample_number; ++i) {
            // skip: subsample_i_data_type
            bytestream2_skip(gbc, (4 + 4) / 8);
            // skip: subsample_i_data_size
            if (length_ext_flag) {
                bytestream2_skip(gbc, 32 / 8);
            } else {
                bytestream2_skip(gbc, 16 / 8);
            }
        }
    }

    if (bytestream2_get_bytes_left(gbc) < data_size)
        return AVERROR_INVALIDDATA;
    if ((err = av_new_packet(ctx->pkt, data_size)) < 0) return err;
    bytestream2_get_bufferu(gbc, ctx->pkt->data, data_size);

    ctx->pkt->stream_index = st->stream->index;
    ctx->pkt->flags        = st->flags;
    ctx->pkt->pos          = st->offset;
    ctx->pkt               = NULL;

    st->flags  = 0;
    st->offset = -1;
    return 0;
}

static int
emit_packet(MMTPContext *ctx, struct Streams *st, uint8_t *data, int size)
{
    int           err;
    int           consumed;
    const uint8_t *out_data = NULL;
    int           out_size  = 0;

    if (st->parser == NULL) {
        st->parser = av_parser_init(st->stream->codecpar->codec_id);
        if (st->parser == NULL) return AVERROR(ENOMEM);
        st->parser->last_pos = 0;
    }

    while (size > 0) {
        if (st->parser->fetch_timestamp) {
            if ((err = fill_pts_dts(st)) < 0)
                return err;
            st->parser->fetch_timestamp = false;
            st->parser->pos             = st->offset;
            // use last_pos to store flags
            st->parser->last_pos        = st->flags;
        }
        st->offset = -1;
        st->flags  = 0;

        consumed = st->parser->parser->parser_parse(
            st->parser, ffstream(st->stream)->avctx,
            &out_data, &out_size,
            data, size
        );
        size -= consumed;

        if (out_data == NULL) {
            continue;
        }
        st->parser->fetch_timestamp = true;

        av_assert0(ctx->pkt->data == NULL);
        ctx->pkt->data = (uint8_t *) out_data;
        ctx->pkt->size = out_size;

        if ((err = av_packet_make_refcounted(ctx->pkt)) < 0)
            return err;

        ctx->pkt->pos          = st->parser->pos;
        ctx->pkt->pts          = st->parser->pts;
        ctx->pkt->dts          = st->parser->dts;
        ctx->pkt->stream_index = st->stream->index;
        ctx->pkt->flags        = st->parser->last_pos;
        if (st->parser->key_frame == 1)
            ctx->pkt->flags |= AV_PKT_FLAG_KEY;
    }
    return 0;
}

static int consume_mfu(MMTPContext *ctx, GetByteContext *gbc)
{
    int            err;
    uint8_t        *buf;
    unsigned int   size;
    struct Streams *st = find_current_stream(ctx);
    av_assert0(st != NULL);

    switch (st->stream->codecpar->codec_id) {
    case AV_CODEC_ID_HEVC:
        size = bytestream2_get_be32(gbc);
        if (size != bytestream2_get_bytes_left(gbc)) return AVERROR_INVALIDDATA;
        if ((buf = av_malloc(size + 3)) == NULL) return AVERROR(ENOMEM);
        buf[0] = 0x00;
        buf[1] = 0x00;
        buf[2] = 0x01;
        bytestream2_get_bufferu(gbc, buf + 3, size);
        err = emit_packet(ctx, st, buf, size + 3);
        av_free(buf);
        return err;
    case AV_CODEC_ID_AAC_LATM:
        size = bytestream2_get_bytes_left(gbc);
        if (size >> 13) return AVERROR(EOVERFLOW);
        if ((buf = av_malloc(size + 3)) == NULL) return AVERROR(ENOMEM);
        buf[0] = 0x56;
        buf[1] = 0xe0 | (size >> 8);
        buf[2] = size & 0xff;
        bytestream2_get_bufferu(gbc, buf + 3, size);
        err = emit_packet(ctx, st, buf, size + 3);
        av_free(buf);
        return err;
    case AV_CODEC_ID_TTML:
        return emit_closed_caption_mfu(ctx, st, gbc);
    default:
        return AVERROR_PATCHWELCOME;
    }
}

static int parse_mfu_timed_data(
    MMTPContext *ctx, struct FragmentAssembler *assembler,
    uint32_t seq_num, enum FragmentationIndicator indicator,
    GetByteContext *gbc)
{
    bytestream2_skip(gbc, (32 + 32 + 32 + 8 + 8) / 8);
    return assemble_fragment(
        assembler, seq_num, indicator,
        gbc->buffer, bytestream2_get_bytes_left(gbc),
        consume_mfu, ctx);
}

static int parse_mfu_non_timed_data(
    MMTPContext *ctx, struct FragmentAssembler *assembler,
    uint32_t seq_num, enum FragmentationIndicator indicator,
    GetByteContext *gbc)
{
    bytestream2_skip(gbc, 32 / 8);
    return assemble_fragment(
        assembler, seq_num, indicator,
        gbc->buffer, bytestream2_get_bytes_left(gbc),
        consume_mfu, ctx);
}

static int parse_mpu(MMTPContext *ctx, uint32_t seq_num, GetByteContext *gbc)
{
    int                         err;
    uint8_t                     byte, fragment_type;
    bool                        timed_flag;
    enum FragmentationIndicator fragmentation_indicator;
    bool                        aggregation_flag;
    uint16_t                    length;
    uint32_t                    mpu_sequence_number;
    struct FragmentAssembler    *assembler;
    struct Streams              *streams;

    streams = find_current_stream(ctx);
    if (streams == NULL || streams->stream->discard >= AVDISCARD_ALL)
        return 0;

    assembler = find_or_allocate_assembler(ctx, ctx->current_pid);
    if (assembler == NULL) return AVERROR(errno);

    if (bytestream2_get_bytes_left(gbc) < (16 + 4 + 1 + 2 + 1 + 8 + 32) / 8)
        return AVERROR_INVALIDDATA;

    length = bytestream2_get_be16u(gbc);
    if (length != bytestream2_get_bytes_left(gbc))
        return AVERROR_INVALIDDATA;

    byte                    = bytestream2_get_byteu(gbc);
    fragment_type           = byte >> 4;
    timed_flag              = (byte >> 3) & 1;
    fragmentation_indicator = (byte >> 1) & 0b11;
    aggregation_flag        = byte & 1;

    // skip: fragment_counter
    bytestream2_skipu(gbc, 1);

    mpu_sequence_number = bytestream2_get_be32u(gbc);

    if (aggregation_flag && fragmentation_indicator != NOT_FRAGMENTED)
        return AVERROR_INVALIDDATA; // cannot be both fragmented and aggregated

    if (fragment_type != 2)
        return 0; // not MFU

    if (assembler->state == INIT && !ctx->is_rap)
        return 0; // wait for the first RAP

    if (assembler->state == INIT) {
        streams->last_sequence_number = mpu_sequence_number;
    } else if (mpu_sequence_number == streams->last_sequence_number + 1) {
        streams->last_sequence_number = mpu_sequence_number;
        streams->au_count             = 0;
    } else if (mpu_sequence_number != streams->last_sequence_number) {
        av_log(streams->stream, AV_LOG_WARNING,
               "MPU sequence number jump: %u + 1 != %u\n",
               streams->last_sequence_number, mpu_sequence_number);
        streams->last_sequence_number = mpu_sequence_number;
        streams->au_count             = 0;
    }

    check_state(ctx, assembler, seq_num);

    if (streams->offset == -1)
        streams->offset = ctx->pkt->pos;

    if (ctx->is_rap)
        streams->flags |= AV_PKT_FLAG_KEY;

    if (timed_flag) {
        if (aggregation_flag) {
            while (bytestream2_get_bytes_left(gbc) > 0) {
                length = bytestream2_get_be16(gbc);
                if (bytestream2_get_bytes_left(gbc) < length)
                    return AVERROR_INVALIDDATA;
                {
                    GetByteContext ngbc;
                    bytestream2_init(&ngbc, gbc->buffer, length);

                    err = parse_mfu_timed_data(
                        ctx, assembler, seq_num, NOT_FRAGMENTED, &ngbc);
                    if (err < 0) return err;
                }
                bytestream2_skipu(gbc, length);
            }
        } else {
            return parse_mfu_timed_data(
                ctx, assembler, seq_num, fragmentation_indicator, gbc);
        }
    } else {
        if (aggregation_flag) {
            while (bytestream2_get_bytes_left(gbc) > 0) {
                length = bytestream2_get_be16(gbc);
                if (bytestream2_get_bytes_left(gbc) < length)
                    return AVERROR_INVALIDDATA;
                {
                    GetByteContext ngbc;
                    bytestream2_init(&ngbc, gbc->buffer, length);

                    err = parse_mfu_non_timed_data(
                        ctx, assembler, seq_num, NOT_FRAGMENTED, &ngbc);
                    if (err < 0) return err;
                }
                bytestream2_skipu(gbc, length);
            }
        } else {
            return parse_mfu_non_timed_data(
                ctx, assembler, seq_num, fragmentation_indicator, gbc);
        }
    }

    return 0;
}

MMTPContext *ff_mmtp_parse_open(AVProgram *program)
{
    MMTPContext *ctx = av_mallocz(sizeof(MMTPContext));
    if (ctx == NULL) return NULL;
    ctx->program = program;
    return ctx;
}

int ff_mmtp_parse_packet(MMTPContext *ctx, AVFormatContext *s, AVPacket *pkt,
                         const uint8_t *buf, uint16_t size)
{
    bool     packet_counter_flag;
    bool     extension_header_flag;
    uint8_t  payload_type;
    uint32_t packet_sequence_number;
    uint8_t  byte;
    int      err = 0;

    GetByteContext gbc;

    ctx->s   = s;
    ctx->pkt = pkt;

    bytestream2_init(&gbc, buf, size);
    if (bytestream2_get_bytes_left(&gbc) <
        (2 + 1 + 2 + 1 + 1 + 1 + 2 + 6 + 16 + 32 + 32) / 8)
        return AVERROR_INVALIDDATA;

    byte                  = bytestream2_get_byteu(&gbc);
    packet_counter_flag   = (byte >> 5) & 1;
    extension_header_flag = (byte >> 1) & 1;
    ctx->is_rap = byte & 1;

    byte         = bytestream2_get_byteu(&gbc);
    payload_type = byte & 0b111111;

    ctx->current_pid = bytestream2_get_be16u(&gbc);

    // skip: distribute_timestamp
    bytestream2_skipu(&gbc, 4);

    packet_sequence_number = bytestream2_get_be32u(&gbc);

    if (packet_counter_flag)
        bytestream2_skip(&gbc, 4);

    if (extension_header_flag) {
        uint16_t extension_header_length;
        // skip: extension_type
        bytestream2_skip(&gbc, 2);
        extension_header_length = bytestream2_get_be16(&gbc);
        bytestream2_skip(&gbc, extension_header_length);
    }

    switch (payload_type) {
    case 0x00: // MPU
        if (pkt != NULL)
            err = parse_mpu(ctx, packet_sequence_number, &gbc);
        break;
    case 0x02: // signalling messages
        err = parse_signalling_messages(ctx, packet_sequence_number, &gbc);
        break;
    }
    if (err < 0) return err;
    return (pkt == NULL || pkt->data != NULL) ? 0 : FFERROR_REDO;
}

void ff_mmtp_reset_state(MMTPContext *ctx)
{
    struct Streams           *streams;
    struct FragmentAssembler *assembler;

    for (assembler = ctx->assembler;
         assembler != NULL; assembler = assembler->next) {
        assembler->state = INIT;
        assembler->size  = 0;
    }
    for (streams = ctx->streams; streams != NULL; streams = streams->next) {
        if (streams->parser != NULL) {
            av_parser_close(streams->parser);
            streams->parser = NULL;
        }
        streams->last_sequence_number = 0;
        streams->au_count             = 0;
        streams->flags                = 0;
        streams->offset               = -1;
    }
}

void ff_mmtp_parse_close(MMTPContext *ctx)
{
    struct FragmentAssembler *ass;
    struct Streams           *streams;

    for (ass = ctx->assembler; ass != NULL;) {
        struct FragmentAssembler *next = ass->next;
        av_free(ass->data);
        av_free(ass);
        ass = next;
    }

    for (streams = ctx->streams; streams != NULL;) {
        struct Streams *next = streams->next;
        if (streams->parser != NULL) av_parser_close(streams->parser);
        av_free(streams->timestamp_descriptor);
        av_free(streams->ext_timestamp_descriptor);
        av_free(streams);
        streams = next;
    }

    av_free(ctx);
}
