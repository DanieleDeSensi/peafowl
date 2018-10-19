/*
 * l7_sub_rules.h
 *
 * Created on: 16/10/2018
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */

#ifndef PFWL_L7_SUB_RULES
#define PFWL_L7_SUB_RULES

#include <peafowl/config.h>
#include <peafowl/peafowl.h>

typedef struct{
  const char* value;               ///< The hostname to match
  uint8_t has_tld;                 ///< If 1, value also contains TLD.
  pfwl_protocol_l7_sub_t protocol; ///< The L7 sub protocol associated to the specified value.
}pfwl_l7_sub_rule_http_host_t;

const pfwl_l7_sub_rule_http_host_t pfwl_l7_sub_rules_http_host[] = {
    ///< Google
    { ".googlesyndication.", 0, PFWL_PROTO_L7_SUB_GOOGLE},
    { "googleads."         , 0, PFWL_PROTO_L7_SUB_GOOGLE},
    { ".doubleclick."      , 0, PFWL_PROTO_L7_SUB_GOOGLE},
    { "googleadservices."  , 0, PFWL_PROTO_L7_SUB_GOOGLE},
    { ".2mdn."             , 0, PFWL_PROTO_L7_SUB_GOOGLE},
    { ".dmtry."            , 0, PFWL_PROTO_L7_SUB_GOOGLE},
    { "google-analytics."  , 0, PFWL_PROTO_L7_SUB_GOOGLE},
    { "gtv1."              , 0, PFWL_PROTO_L7_SUB_GOOGLE},

    ///< Amazon video
    { "s3.ll.dash.row.aiv-cdn.net"    , 1, PFWL_PROTO_L7_SUB_AMAZON_VIDEO},
    { "s3-dub.cf.dash.row.aiv-cdn.net", 1, PFWL_PROTO_L7_SUB_AMAZON_VIDEO},
    { "dmqdd6hw24ucf.cloudfront.net"  , 1, PFWL_PROTO_L7_SUB_AMAZON_VIDEO},
    { "d25xi40x97liuc.cloudfront.net" , 1, PFWL_PROTO_L7_SUB_AMAZON_VIDEO},
    { ".aiv-delivery.net"             , 1, PFWL_PROTO_L7_SUB_AMAZON_VIDEO},
};

#endif
