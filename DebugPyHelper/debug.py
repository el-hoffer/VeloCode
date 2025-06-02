#!/usr/bin/python3

from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
from builtins import zip
from builtins import str
from builtins import hex
from builtins import range
from builtins import object
import datetime
import sys
import pwd
import os.path
sys.path.insert(0, '/opt/vc/lib/python')
# Source tree:
sys.path.insert(1, os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../common/pylibs'))

#vc_qos tree display function
from vc_qos_view import *

import errno
import os
import time
import signal
import shlex
import subprocess
import argparse
import json
import subprocess
import fcntl
import operator
import syslog
import socket
import struct
from tinyrpc.exc import RPCError
import re
from pyutil import rpc
from pyutil import pki
from pyutil import utils
from operator import attrgetter
from functools import partial
import hardware
import hardwareinfo
import monitor.base
import monitor.cpu
import monitor.mem
import mgd.client_connector_common as cc_common

WAN_LINKS = sorted(hardware.DEFAULT_INTERNET_LINKS.keys())+sorted(hardware.USB_PATHS.keys())

# Timeout: None == default(2), <= 0 means block forever
USER_TIMEOUT_SECS = 2
LOGFILE = "NIL"
LACP_BOND_DIR = "/proc/net/bonding/"
#TODO change this to the correct prefix once we finalize - Badri/Vikas
LACP_BOND_PREFIX = "bond-"

def log_datetime():
    now = datetime.datetime.now()
    formatted_datetime = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]  # Trim to milliseconds
    return formatted_datetime

def get_value(values, index, default):
    return values[index] if index < len(values) else default

def proto_str(proto, flow):
    if proto == 6:
        return "TCP"
    elif proto == 17:
        return "UDP"
    elif proto == 1:
        return "ICMP"
    elif proto == 58:
        return "ICMPv6"
    elif proto == 47:
        return "GRE"
    else:
        return str(proto)

def port_formatter(value, flow):
    # Currently proto such as GRE/ICMP makes use of srcPort field, so we return
    # N/A only when srcPort/dstPort is 0. Otherwise return the value as it is
    if value == 0:
        return 'N/A'
    return str(value)

def millisecs_formatter(value, flow):
    # convert milliseconds to something more human readable
    if value == 0:
        return '0 ms'

    days = hours = minutes = seconds = millisecs = 0
    if value >= 86400000:
        days = value // 86400000 # ms per day
        value %= 86400000
    if value >= 3600000:
        hours = value // 3600000 # ms per hour
        value %= 3600000
    if value >= 60000:
        minutes = value // 60000 # ms per min
        value %= 60000
    if value >= 1000:
        seconds = value // 1000 # ms per sec
        value %= 1000
    millisecs = value

    if days:
        return '{}d {:0>2}:{:0>2}:{:0>2}.{:0>3}'.format(days, hours, minutes, seconds, millisecs)
    if hours:
        return '{}:{:0>2}:{:0>2}.{:0>3}'.format(hours, minutes, seconds, millisecs)
    if minutes:
        return '{}:{:0>2}.{:0>3}'.format(minutes, seconds, millisecs)
    if seconds:
        return '{}.{:0>3}'.format(seconds, millisecs)

    return '{} ms'.format(millisecs)

def seconds_formatter(value, flow):
    # convert seconds to something more human readable
    if value == 0:
        return '0 s'

    days = hours = minutes = seconds = 0
    if value >= 86400:
        days = value // 86400 # secs  per day
        value %= 86400
    if value >= 3600:
        hours = value // 3600 # secs per hour
        value %= 3600
    if value >= 60:
        minutes = value // 60 # secs  per min
        value %= 60
    seconds = value

    if days:
        return '{}d {:0>2}:{:0>2}:{:0>2}'.format(days, hours, minutes, seconds)
    if hours:
        return '{}:{:0>2}:{:0>2}'.format(hours, minutes, seconds)
    if minutes:
        return '{}:{:0>2}'.format(minutes, seconds)

    return '{} s'.format(seconds)

def bytes_formatter(value, flow):
    if value >= 1099511627776:
        tib = float(value) / 1099511627776 # bytes per TiB
        return '{:.1f} TiB'.format(tib)
    if value >= 1073741824:
        gib = float(value) / 1073741824 # bytes per GiB
        return '{:.1f} GiB'.format(gib)
    if value >= 1048576:
        mib = float(value) / 1048576 # bytes per MiB
        return '{:.1f} MiB'.format(mib)
    if value >= 1024:
        kib = float(value) / 1024 # bytes per KiB
        return '{:.1f} KiB'.format(kib)
    return '{} B'.format(value)

def bool_formatter(value, flow):
    if value:
        return 'True'
    return 'False'

def get_fmt(t):
    if len(t) >= 3:
        return lambda value, flow: '?' if value == '?' else t[2](value, flow)
    return lambda value, flow: str(value)

def json_table_generator(json, mapping):
    # json is an array of Json objects
    # mapping is an array of 2 or 3-tuples that maps table column headings
    # to Json keys with optional formatter functions

    # First row in the table will be column headings, even if the JSON is empty
    yield [t[0] for t in mapping]

    cnt = 1
    for obj in json:
        if cnt % 50 == 0:
            yield [t[0] for t in mapping]

        yield [get_fmt(t)(obj.get(t[1], '?'), obj) for t in mapping]

        cnt += 1

class setLogfileAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        global LOGFILE
        LOGFILE = values[0]

class setTimeoutAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        global USER_TIMEOUT_SECS
        USER_TIMEOUT_SECS = int(values[0])

def get_timeout_ms(namespace):
    return USER_TIMEOUT_SECS * 1000

def get_entry_limit(namespace):
    return int(namespace.limit[0])

def notify_truncated_output(truncated):
    if truncated == True:
        sys.stderr.write("Output was truncated\n")

def ip_mask_to_prefix_len(mask):
    mask = struct.unpack(">I", socket.inet_pton(socket.AF_INET, mask))[0]
    if mask == 0:
        return 0

    len = 0
    while (mask & 1) == 0:
        len += 1
        mask >>= 1

    return 32 - len

def process_filter_params(params, filters, values):
    for i in range(0, len(values)):
        if "=" in values[i]:
            pair = values[i].split("=", 1)
            if not pair[0] in filters:
                print("Invalid filter: " + pair[0])
                sys.exit(0)
            try:
                params.update({pair[0]:int(pair[1])})
            except:
                params.update({pair[0]:pair[1]})
        else:
            print("Invalid filter: " + values[i])
            sys.exit(0)

def handler(signum, frame):
    print(os.strerror(errno.ETIMEDOUT))
    os._exit(1)

def is_float(str):
    try:
        float(str)
        return True
    except ValueError:
        return False

class verboseBizPolDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 1):
                params = {"debug":"biz","segid":values[0],"policy-name":"all"}
            if (len(values) == 2):
                params = {"debug":"biz","segid":values[0],"policy-name":values[1]}
        else:
            params = {"debug":"biz","segid":"all","policy-name":"all"}

        reply = remote_server.bizPolicyDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class BizPolDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 1):
                params = {"debug":"biz","segid":values[0],"policy-name":"all"}
            if (len(values) == 2):
                params = {"debug":"biz","segid":values[0],"policy-name":values[1]}
        else:
            params = {"debug":"biz","segid":"all","policy-name":"all"}

        reply = remote_server.bizPolicyDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        biz_pol = []
        biz_pol.append(["Name", "Seg", "CBH", "Hits", "RouteType", "Prio", "TrafficType", " | ",
                        "Routepolicy", "ServiceGroup", "LinkPolicy", "LinkMode", "Interface", "LinkLogId", "ErrorCorrection"])
        policy = reply["policies"]

        for entry in policy:
            if entry["routeType"] == "E2E":
                action = entry["e2eRouteAction"]
            elif entry["routeType"] == "E2DC":
                action = entry["e2dcRouteAction"]
            elif entry["routeType"] == "E2C":
                action = entry["e2cRouteAction"]
            else:
                action = entry["e2cRouteAction"]
            qos = entry["qos"]

            biz_pol.append([entry["name"], str(entry["seg"]),
                            str(entry["allowConditionalBh"]), str(entry["hits"]), entry["routeType"],
                            entry["statPriority"], qos["traffictype"], " | ",
                            action["routePolicy"], action["serviceGroup"], action["linkPolicy"],
                            action["linkMode"], action["interface"], action["linkLogicalId"], action["errorCorrection"]])

        pretty_print_table(biz_pol)

class NetFlowIntervals(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"netflow","command":"intervals"}

        reply = remote_server.netFlowDebugDump(**params)

        if reply == None:
            return

        print(json.dumps(reply, sort_keys = True, indent = 2))
        return

class NetFlowCollectors(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"netflow", "command":"collectors"}

        reply = remote_server.netFlowDebugDump(**params)

        if reply is not None:
            collectors = reply
        else:
            return

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        collector_array = []
        collector_array.append(["CollectorId", "SegmentId", "IP", "Port", "AllowAll", "SourceIP", "SourceInterface", "InterfaceSelection"])

        for collector in collectors:
            collector_id = collector["collector_id"]
            collector_array.append([str(collector_id), str(collector["segment_id"]), str(collector["collector_ip"]),
                                    str(collector["collector_port"]), str(collector["allow_all"]),
                                    str(collector["source_ip"]), str(collector["source_interface"]), collector["iface_selection"]])
        pretty_print_table(collector_array)

class NetFlowFilters(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"netflow", "command": "filters", "args":{"collectorId": values[0]}}

        reply = remote_server.netFlowDebugDump(**params)

        if reply is not None:
            filters = reply
        else:
            return

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        filter_array = []
        filter_array.append(["Index", "Hits", "SrcIP", "SrcMask", "DstIP", "DstMask", "DstPort Low", "DstPort High", "Proto", "AppId", "ClassId", "Action"])

        count = 0;
        for filter in filters:
            if filter["deny"] == True:
                action = "Deny"
            else:
                action = "Allow"

            count = count + 1;
            filter_array.append([str(count), str(filter["hits"]), str(filter["src_ip"]), str(filter["src_mask"]),
                                 str(filter["dst_ip"]), str(filter["dst_mask"]), str(filter["dst_port_low"]), str(filter["dst_port_high"]),
                                 str(filter["proto"]), str(filter["app_id"]), str(filter["class_id"]), action])

        pretty_print_table(filter_array)
        return

class lanSideNatDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):

        params = {"debug":"lanSideNat"}
        reply = remote_server.vpnViaNatDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        result = []
        print("====================== Source or Destination NAT ====================")

        result.append(["Type", "Segment ID", "Inside Cidr IP", "Outside Cidr IP", "Source Route",
            "Destination Route", "Identity", "Force PAT", "Hits"])

        segments = reply["segments"]
        for segment in segments:
            segment_id = str(segment["segment"])
            for entry in segment["rules"]:
                if entry["insideCidrIp"] != "any":
                    inside_cidr_ip = entry["insideCidrIp"] + "/" + str(entry["insideCidrPrefix"])
                else:
                    inside_cidr_ip = entry["insideCidrIp"]
                if entry["outsideCidrIp"] != "any":
                    outside_cidr_ip = entry["outsideCidrIp"] + "/" + str(entry["outsideCidrPrefix"])
                else:
                    outside_cidr_ip = entry["outsideCidrIp"]
                if entry["srcCidrIp"] != "any" and entry["srcCidrIp"] != "N/A":
                    source_ip = entry["srcCidrIp"] + "/" + str(entry["srcCidrPrefix"])
                else:
                    source_ip = entry["srcCidrIp"]
                if entry["destCidrIp"] != "any" and entry["destCidrIp"] != "N/A":
                    dest_ip = entry["destCidrIp"] + "/" + str(entry["destCidrPrefix"])
                else:
                    dest_ip = entry["destCidrIp"]
                force_pat = "None"
                if entry["forcePatToWan"]:
                    force_pat = "ToWAN";
                if entry["forcePatToLan"]:
                    force_pat = "ToLAN";
                result.append([entry["type"], segment_id, inside_cidr_ip, outside_cidr_ip,
                    source_ip, dest_ip, str(entry["identity"]), force_pat, str(entry["hits"])])

        pretty_print_table(result)

        print("\n====================== Source and Destination NAT ====================")

        result = []
        result.append(["Segment ID", "SrcInsideIp", "SrcOutsideIp",
            "DestInsideIp", "DestOutsideIp", "Identity", "Force PAT", "Hits"])

        segments = reply["segments"]
        for segment in segments:
            segment_id = str(segment["segment"])
            for entry in segment["dualNatRules"]:
                if entry["srcInsideCidrIp"] != "any":
                    inside_src_ip = entry["srcInsideCidrIp"] + "/" + str(entry["srcInsideCidrPrefix"])
                else:
                    inside_src_ip = entry["srcInsideCidrIp"]
                if entry["srcOutsideCidrIp"] != "any":
                    outside_src_ip = entry["srcOutsideCidrIp"] + "/" + str(entry["srcOutsideCidrPrefix"])
                else:
                    outside_src_ip = entry["srcOutsideCidrIp"]
                if entry["destInsideCidrIp"] != "any":
                    inside_dest_ip = entry["destInsideCidrIp"] + "/" + str(entry["destInsideCidrPrefix"])
                else:
                    inside_dest_ip = entry["destInsideCidrIp"]
                if entry["destOutsideCidrIp"] != "any":
                    outside_dest_ip = entry["destOutsideCidrIp"] + "/" + str(entry["destOutsideCidrPrefix"])
                else:
                    outside_dest_ip = entry["destOutsideCidrIp"]
                force_pat = "None"
                if entry["forcePatToWan"]:
                    force_pat = "ToWAN";
                if entry["forcePatToLan"]:
                    force_pat = "ToLAN";
                result.append([segment_id, inside_src_ip, outside_src_ip,
                    inside_dest_ip, outside_dest_ip, str(entry["identity"]), force_pat,
                    str(entry["hits"])])

        pretty_print_table(result)

class verboseFirewallDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            segopt = values[0]
            family = "all"
        elif len(values) == 2:
            segopt = values[0]
            family = values[1]
        else:
            segopt = "all"
            family = "all"

        params = {"debug":"firewall","segid":segopt,"family":family}

        reply = remote_server.firewallDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

def print_pretty_inbound_table(inbound):
    print("------------------PORT FORWARDING------------------")
    output = []
    output.append(["Name", "Protocol", "Interface", "Outside IP",
                   "WAN Port(s)", "LAN IP", "LAN Port", "Segment Id", "Hits"])
    for val in inbound:
        match = val["match"]
        action = val["action"]
        if action["type"] == "port forwarding":
            protocol = "TCP"
            if match["proto"] == 17:
                protocol = "UDP"
            port = str(match["dport_low"])
            if match["dport_low"] != match["dport_high"]:
                port = str(match["dport_low"]) + "-" + str(match["dport_high"])
            output.append([val["name"], protocol, action["interface"], match["dip"], port,
                    action["lan_ip"], str(action["lan_port"]),
                    str(action["segment_id"]), str(val["hits"])])
    pretty_print_table(output)
    print("\n------------------ONE-TO-ONE NAT-------------------")
    output = []
    output.append(["Name", "Interface", "Outside IP", "Inside IP", "Bidirectional",
                    "Allowed Protocol", "Allowed Port(s)", "Segment Id", "Hits"])
    for val in inbound:
        match = val["match"]
        action = val["action"]
        if action["type"] == "one-to-one nat":
            protocol = "TCP"
            if match["proto"] == 17:
                protocol = "UDP"
            elif match["proto"] == 1:
                protocol = "ICMP"
            elif match["proto"] == 58:
                protocol = "ICMPv6"
            elif match["proto"] == 47:
                protocol = "GRE"
            elif match["proto"] == -1:
                protocol = "ALL"
            port = str(match["dport_low"])
            if port == "-1":
                port = "ALL"
            elif match["dport_low"] != match["dport_high"]:
                port = str(match["dport_low"]) + "-" + str(match["dport_high"])
            bidirectional = "FALSE"
            if action["bidirectional"]:
                bidirectional = "TRUE"
            output.append([val["name"], action["interface"], match["dip"],
                          action["lan_ip"], bidirectional, protocol, port,
                          str(action["segment_id"]), str(val["hits"])])
    pretty_print_table(output)

class FirewallDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            segopt = values[0]
            family = "all"
        elif len(values) == 2:
            segopt = values[0]
            family = values[1]
        else:
            segopt = "all"
            family = "all"

        params = {"debug":"firewall","segid":segopt,"family":family}

        reply = remote_server.firewallDebugDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        policy = reply["firewall"]
        for entry in policy:
            if "outbound" not in entry:
                print(json.dumps(policy, sort_keys = True, indent = 2))
                return
            print()
            print("Stateful Firewall : %s" % (
                        "Enabled" if entry["stateful_firewall"] else "Disabled"))
            print("EFS Status : %s" % (
                        "Enabled" if entry["efs_enabled"] else "Disabled"))
            efs_features = entry["efs_features"]
            if efs_features:
                print("URL Filtering : %s" % (
                      "Enabled" if efs_features["url_filtering"] else "Disabled"))
                print("Malicious IP Filtering : %s" % (
                      "Enabled" if efs_features["mal_ip_filtering"] else "Disabled"))
                print("IDPS : %s" % (
                      "Enabled" if efs_features["idps"] else "Disabled"))

            print("Firewall logging for segment", entry["seg"])
            print("Global firewall logging  : %s" %  (
                        "Enabled" if entry["global_firewall_logging"] else "Disabled"))
            print("====================== FIREWALL ====================")
            print("--------------- Firewall Rules ---------------")
            output = []
            output.append(["Name", "Hits", "Action"])
            outbound = entry["outbound"]
            for val in outbound:
                if val["efs_present"] == True:
                    continue
                action = val["action"]
                output.append([val["name"], str(val["hits"]), action["allow_or_deny"]])
            pretty_print_table(output)

            print("\n------------- NextGen Firewall Rules -------------")
            output = []
            output.append(["Name",  "Hits", "IDS", "IPS","URL_CAT_FILTER",
                          "URL_REP_FILTER", "MAL_IP_FILTER"])
            for val in outbound:
                if val["efs_present"] == True:
                    idps_action = val.get("idps_action")
                    if val.get("idps_action") is not None:
                        ids_enable = idps_action["ids_enabled"]
                        ips_enable = idps_action["ips_enabled"]
                    else:
                        ids_enable = 0
                        ips_enable = 0

                    output.append([val["name"], str(val["hits"]),
                                 "Enabled" if ids_enable else "Disabled",
                                 "Enabled" if ips_enable else "Disabled",
                                 "Enabled" if val.get("url_category_filtering") else "Disabled",
                                 "Enabled" if val.get("url_reputation_filtering") else "Disabled",
                                 "Enabled" if val.get("malicious_ip_filtering") else "Disabled"])
            pretty_print_table(output)

            if(family == "all" or family == "v4"):
                print("\n====================== INBOUND INTERNET ACL ====================")
                print_pretty_inbound_table(entry["inbound"])
            if(family == "all" or family == "v6"):
                print("\n====================== INBOUND INTERNET V6 ACL ====================")
                print_pretty_inbound_table(entry["inboundV6"])

class StaleFlowDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            params = {"debug": "stale_flow_dump", "val":1, "dip": values}
        else:
            params = {"debug": "stale_flow_dump", "val":1, "dip": "all"}

        output = []
        output.append(["PTR", "FC_ID", "SIP", "DIP", "SPORT", "DPORT", "DSCP", "DEAD SINCE", "REF OBJS", "RTQ PKTS"])
        reply = remote_server.dumpStaleFlows(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        stale_flows = reply['stale_flows']
        for stale_flow in stale_flows:
            output.append([str(stale_flow['flow_ptr']), str(stale_flow['flow_id']), str(stale_flow['sip']), str(stale_flow['dip']),
                           str(stale_flow['sport']), str(stale_flow['dport']), str(stale_flow['dscp']), str(stale_flow['dead_since']),
                           str(stale_flow['ref_objs']), str(stale_flow['pkts_in_rt_queue'])])
        if len(output) > 0:
            pretty_print_table(output)

class UflowDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"uflowdump", "sip": values[0], "dip": values[1],"seg":values[2] ,
                 "limit": get_entry_limit(namespace), "timeout_ms": get_timeout_ms(namespace)//10,
                 "logfile": LOGFILE}
        reply = remote_server.uFlowDebugDump(**params)
        if LOGFILE != "NIL":
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        truncated = reply["truncated"]
        reply = reply["vce_uflows"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        output = []
        output.append(["SEG_ID", "SRC_IP", "DEST_IP", "SRC_PORT", "DEST_PORT",
                       "PROTO", "DSCP", "USERS", "ACTIVE_FC_REFS"]);
        for uflow in reply:
            output.append([str(uflow["segment_id"]), uflow["src_ip_addr"], uflow["dst_ip_addr"],
                           str(uflow["src_port"]), str(uflow["dst_port"]), str(uflow["protocol"]),
                           str(uflow["dscp"]), str(uflow["users"]), str(uflow["active_fc_refs"])])
        if len(output) > 0:
            pretty_print_table(output)

        notify_truncated_output(truncated)

class qatDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        reply = remote_server.qat_dump({})
        print(json.dumps(reply, sort_keys =False, indent = 2))
        return

class FlowDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):

        if len(values) < 3:
            print("""Insufficient Arguments provided. Minimum number of argument is 3.
                  usage: --flow_dump [local | logical-id | all] [all | dest-ip] [all | segid]""")
            return
        if len(values) > 4:
            print("""Invalid no.of arguments provided. Maximum no.of argument is 4.
                  usage: --flow_dump [local | logical-id | all] [all | dest-ip] [all | segid]
                         [v4 | v6 |all]
                         --flow_route_dump [local | logical-id | all] [all | dest-ip] [all | segid]
                         [flow_id | noroute]""")
            return
        routeopt = "noroute"
        params = {"debug": "flowdump", "logical_id": values[0], "dip": values[1], "seg": values[2],
                  "limit": get_entry_limit(namespace), "ip_fam": "all", "route": routeopt,
                  "timeout_ms": get_timeout_ms(namespace) // 10, "logfile": LOGFILE}

        if len(values) == 4:
            if values[3] in ["v4", "v6", "all"]:
                params.update({"ip_fam": values[3]})
            else:
                routeopt = values[3]
                params.update({"route": routeopt})

        reply = remote_server.flowDebugDump(**params)
        if LOGFILE != "NIL":
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        reply = reply["vce_flows"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        if routeopt == "noroute":
            cnt = 0
            output = []
            for vce_flows in reply:
                flows = vce_flows["flows"]
                for flow in flows:
                    if (cnt == 0) or (cnt % 50 == 0):
                        output.append(["FID", "SECURE", "SEGID", "FDSN", "MAX_RECV_FDSN",
                                       "FDSN_READ", "LAST_LATE_FDSN", "SRC_IP", "DEST_IP",
                                       "SRC_PORT", "DEST_PORT", "PROTO", "DSCP", "PRIORITY",
                                       "APPLICATION", "APP_CLASS", "TRAFFIC-TYPE", "ROUTE",
                                       "ROUTE-POL", "LINK-POL", "BIZ-POL", "NH-ID", "LINK-ID",
                                       "FLAGS1", "VERSION", "SRC", "ADDR", "SR", "DR",
                                       "FLOW AGE MS", "IDLE TIME MS", "CBH-FLOW",
                                       "BYTES_SENT", "BYTES_RCVD", "PKTS_SENT",
                                       "PKTS_RCVD", "DROPS","LAST_DROPPED_REASON",
                                       "LAST_DROPPED_PATH","BIZ_POL_FIXUP"])
                    output.append([str(flow["flowId"]), str(flow["secure"]),
                                   str(flow["segmentId"]), str(flow["fdsn"]),
                                   str(flow["max_recv_fdsn"]), str(flow["fdsn_read"]),
                                   str(flow["last_late_fdsn"]), flow["srcIP"], flow["destIP"],
                                   str(flow["srcPort"]), str(flow["destPort"]), str(flow["proto"]),
                                   str(flow["dscp"]), flow["priority"],
                                   format_app_string(flow["appProto"], flow["appProtoString"]),
                                   format_app_string(flow["appClass"], flow["appClassString"]),
                                   flow["type"], flow["routeString"], flow["route"], flow["link"],
                                   flow["bizPolicy"], flow["peerId"][:9], flow["linkId"][:9],
                                   str(hex((flow["flags1"] & 0xffffffffffffffff))),
                                   str(flow["version"]), flow["init_src"], flow["address"],
                                   flow["sroute"], flow["droute"], str(flow["ageMs"]),
                                   str(flow["idleTimeMs"]), str(flow["cbhFlow"]),
                                   str(flow["bytes_sent"]), str(flow["bytes_rcvd"]),
                                   str(flow["pkts_sent"]), str(flow["pkts_rcvd"]),
                                   str(flow["drops"]), flow["last_dropped_pkt_reason"],
                                   flow["last_dropped_pkt_path"], str(flow["bizPolicyFixup"])])
                    cnt = cnt + 1
            if len(output) > 0:
                pretty_print_table(output)
        else:
            routes = []
            routes.append(["Address", "Netmask", "Type", "Gateway", "Next Hop ID", "Dst LogicalId",
                           "Reachable", "Metric", "Preference", "Flags", "Vlan", "Intf",
                           "Sub-Intf-Id", "MTU"])
            for vce_flows in reply:
                for entry in vce_flows["flows"]:
                    vlan_id = str(entry["vlan_id"])
                    if vlan_id == "524287":
                        vlan_id = "N/A"
                    sub_intf_id = str(entry["sub_intf_id"])
                    if sub_intf_id == "-1":
                        sub_intf_id = "N/A"
                    routes.append([entry["addr"], entry["netmask"], entry["type"],
                                  entry["gateway"], entry["nhId"], entry["logicalId"],
                                  str(entry["reachable"]), str(entry["metric"]),
                                  str(entry["preference"]), str(entry["flags"]), vlan_id,
                                  entry["intf"], sub_intf_id, entry["mtu"]])

            pretty_print_table(routes)
            legend_str = "P - PG, D - DCE, L - LAN SR, C - Connected, O - External, W - WAN SR, "\
                         "S - SecureEligible, R - Remote, s - self, r - recursive, H - HA, "\
                         "m - Management, n - nonVelocloud, "\
                         "v - ViaVeloCloud, A - RouterAdvertisement, "\
                         "c - CWS, a - RAS, b - Blackhole, I - IPSec, G - GRE"
            print(legend_str)

        notify_truncated_output(truncated)

class StaleTdDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "stale_td_dump"}
        reply = remote_server.dumpStaleTds(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["TD", "PI", "PEER IP", "PEER TYPE", "VERSION", "STATE",
                       "PHY INTF NAME", "REF OBJS", "DURATION"])
        stale_tds = reply['stale_tds']
        for stale_td in stale_tds:
            output.append([str(stale_td["td"]), str(stale_td["pi"]),
                           str(stale_td["peer_ip"]), str(stale_td["peer_type"]),
                           str(stale_td["version"]), str(stale_td["state"]),
                           str(stale_td["phy_intf_name"]), str(stale_td["ref_objs"]),
                           str(stale_td["dead_since_ms"])])
        if len(output) > 0:
            pretty_print_table(output)

class TransientTdDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "transient_td_dump"}
        reply = remote_server.dumpTransientTd(**params)
        if len(reply) > 0:
            print("Number of transient tunnels: " + str(len(reply)))
            print(json.dumps(reply, sort_keys = True, indent = 2))
        else:
            print("No transient paths found")

class StalePiDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "stale_pi_dump"}
        reply = remote_server.dumpStalePi(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["PI", "PEER LOGICAL ID", "PEER TYPE", "OBJ STATE", "REF OBJS", "DURATION"])
        stale_pis = reply['stale_pi']
        for stale_pi in stale_pis:
            output.append([str(stale_pi["pi"]), str(stale_pi["peer_logical_id"]),
                           str(stale_pi["peer_type"]), str(stale_pi["obj_state"]),
                           str(stale_pi["ref_objs"]), str(stale_pi["dead_since_ms"])])
        if len(output) > 0:
            pretty_print_table(output)

class routeEventStatsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            params = {"debug": "rt_event","val": 2,"logical_id": values }
        else:
            params = {"debug": "rt_event", "val": 2, "logical_id": "all" }
        reply = remote_server.dumpRouteEventStats(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class routeStatsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) < 4:
            print("Insufficinet Arguments")
            return

        params = {"debug": "rt_stats", "src_id": values[0], "nhop_id": values[1],
                  "segid": values[2], "rtype": values[3]}

        reply = remote_server.dumpRouteStats(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))
        return

class PacketTracker(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) < 6:
            print("Insufficinet Arguments")
            return

        params = {"debug": "pkt_track", "sip": values[0], "sport": values[1],
                  "dip": values[2], "dport": values[3], "proto": values[4],
                  "count": int(values[5])}

        print(params)
        reply = remote_server.pktTrace(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

        return

class reloadConfigs(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "reload_configs"}
        reply = remote_server.reloadConfigs(**params)

class dumpPlpmtudMTU(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (values):
            filterStr = values
        else:
            filterStr = "all"
        params = {"debug": "dump_pmtud", "filter":filterStr}
        reply = remote_server.dumpPlpmtudMTU(**params)
        if reply.get("Error") != None:
            print(json.dumps(reply, sort_keys = True, indent = 2))
        else:
            #output = []
            #paths = reply.get("paths")
            #output.append(["Interface", "InterfaceIP", "LocalPublicIP", "RemotePublicIP", "PathVersion", "PeerType", "PathStatus","ProbeSize", "ProbeState", "MTU"])
            #for path in paths:
            #    output.append([str(path["iface"]), str(path["iface_ip"]), str(path["local_public_ip"]), str(path["remote_public_ip"]), str(path["path_version"]),
            #        str(path["peer_role"]), str(path["path_status"]), str(path["probe_size"]), str(path["probe_state"]), str(path["mtu"])])
            #pretty_print_table(output)
            print(json.dumps(reply, sort_keys = True, indent = 2))

class runPmtudOnAllPaths(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (values):
            filterStr = values
        else:
            filterStr = "all"
        params = {"debug": "run_pmtud", "filter":filterStr}
        reply = remote_server.runMtupPmtud(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class JitterDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"mpflowJitterBufEnDump"}
        reply = remote_server.mpflowJitterBufEnDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["FDSN", "FDSN_READ", "LAST_LATE_FDSN", "DEP_INTERVAL",
                       "JBUF_ENQUEUE", "JBUF_DEQUEUE", "JBUF_TDEQUEUE", "SRC IP", "DEST IP",
                       "SRC PORT", "DEST PORT", "PROTO", "DSCP", "APPLICATION", "APP CLASS"])
        for flow in reply:
            output.append([str(flow["fdsn"]), str(flow["fdsn_read"]),
                           str(flow["last_late_fdsn"]), str(flow["depInterval"]), str(flow["jbufEnqueueCnt"]),
                           str(flow["jbufDequeueCnt"]), str(flow["jbufRealDequeueCnt"]), flow["srcIP"], flow["destIP"],
                           str(flow["srcPort"]), str(flow["destPort"]), str(flow["proto"]), str(flow["dscp"]),
                           format_app_string(flow["appProto"], flow["appProtoString"]),
                           format_app_string(flow["appClass"], flow["appClassString"])])
        pretty_print_table(output)

class FlowFlushAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            params = {"debug":"flowflush", "fid": int(values)}
        else:
            params = {"debug":"flowflush", "fid": -1}
        reply = remote_server.flowDebugFlush(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class FlowSetIdpsState(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        err_str = "   usage: --flow_set_idps_state [flow-id] [allow | block]"
        if len(values)==2:
            params = {"debug":"FlowSetIdpsState", "fid": int(values[0]), "action": values[1]}
        else:
            print("Insufficient Arguments provided. Minimum number of argument 2.\n" + err_str)
            return

        if values[1] != "allow" and values[1] != "block":
            print("Invalid argument [2]" + err_str)
            return
        reply = remote_server.flowDebugSetIdpsState(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class FlowSetTimeout(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) < 2:
            print("Insufficient Arguments")
            return

        params = {"debug": "flowtimeout", "protocol": values[0], "timeout": int(values[1])}
        reply = remote_server.flowDebugSetTimeout(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class flowTraceAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {}
        for val in values:
            if val == "v4":
                params.update({"ip_version": 4})
            elif val == "v6":
                params.update({"ip_version": 6})
            else:
                kv = val.split("=")
                k, v = kv[0], kv[1]
                if k in ["src_ip", "dst_ip"]:
                    if "." in v:
                        v = "::ffff:" + v
                else:
                    v = int(v)
                params[k] = v

        if len(params) == 0:
            params = { "count": 0 }

        reply = remote_server.flowTrace(**params)
        print(reply)

class natDeleteAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) < 7:
            print("Insufficient Arguments")
            return

        params = {"seg": values[0], "sip": values[1], "sport": values[2],
                  "dip": values[3], "dport": values[4],
                  "proto": values[5], "nat_type": values[6]}
        reply = remote_server.natDelete(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class natDbFlushAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"natdbDebugFlush", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        reply = remote_server.natdbDebugFlush(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class clockSyncAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"clock_sync"}
        reply = remote_server.clockSyncDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class timerSyncAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"timer"}
        reply = remote_server.timerDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class pathStatsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"path_stats", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return

        reply = remote_server.pathStatsDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["Interface", "VLAN", "prio8021P", "PeerName", "PublicIpAddr", "PeerIpAddr", "TunnelingMode", "Version","Path State" ,"RxState", "TxState", "AvgLatencyRx", "AvgLatencyTx", "RxJitter",
                       "TxJitter", "lossRx", "lossTx", "MeasuredRateRx",
                       "MeasuredRateTx",  "dynamicBwRx", "dynamicBwTx", "RemoteRx", "HeartbeatIntervalMs", "MTU",
                       "Dynamic", "Dir", "Overhead", "DynAbort", "LocalGateway"])
        for entry in reply:
            if "path" in entry:
                path = entry["path"]
                vlan_id = "NONE";
                priority = "NONE";
                if entry["vlanId"] != 0:
                    vlan_id = str(entry["vlanId"])
                    priority = format(entry["prio8021P"], '03b')
                output.append([path["interface"], vlan_id, priority, path["peer_name"], path["ipAddress"], path["gateway"],
                   path["tunnelingMode"], str(path["version"]), entry["pathState"] ,entry["pathStateRx"],
                               entry["pathStateTx"], str(entry["avgLatencyRx"]),
                               str(entry["avgLatencyTx"]), str(round(entry["jitterRx"], 1)),
                               str(round(entry["jitterTx"], 1)),str(round(entry["lossRx"], 2)),
                               str(round(entry["lossTx"], 2)), str(entry["measuredRateRx"]),
                               str(entry["measuredRateTx"]),
                               str(entry["dynamicBwRx"]), str(entry["dynamicBwTx"]),
                               str(entry["remoteRx"]), str(entry["heartbeatIntervalMs"]), str(entry["mtu"]),
                               entry["dynamic"], entry["direction"],
                               str(entry["overheadBytes"]),
                               str(entry["linkDynAbort"]), str(entry["localGateway"])])
            else:
                print(json.dumps(reply, sort_keys = True, indent = 2))
                return
        pretty_print_table(output)

class pathStatsSummaryAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"path_stats"}
        reply = remote_server.pathStatsDebugDump(**params)
        params_gw = {"debug":"gateway_dump"}
        reply_gw = remote_server.gatewayListDump(**params_gw)
        gw_name = []
        #reply_gw_info = reply_gw["gwinfo"]
        for val in reply_gw:
            gw_name.append(val["Name"])

        output = []

        edge_total = 0;
        edge_stable = 0;
        edge_unstable = 0;
        edge_init = 0;
        edge_dead = 0;
        edge_unusable = 0;
        edge_quiet = 0;
        edge_measuring = 0;
        edge_unmeasurable = 0;
        edge_waiting = 0;
        edge_dynamic = 0;
        edge_static = 0;

        gw_total = 0;
        gw_stable = 0;
        gw_unstable = 0;
        gw_init = 0;
        gw_dead = 0;
        gw_unusable = 0;
        gw_quiet = 0;
        gw_measuring = 0;
        gw_unmeasurable = 0;
        gw_waiting = 0;

        peer_edges = 0;
        peer_gw = 0;
        peer_name = "";

        for entry in reply:
            if "path" in entry:
                path = entry["path"]
                if path["peer_name"] not in gw_name:
                    edge_total += 1;
                    if peer_name != path["peer_name"]:
                        peer_name = path["peer_name"];
                        peer_edges += 1;
                    if entry["pathStateTx"] == "STABLE" and entry["pathStateRx"] == "STABLE":
                        edge_stable += 1;
                    if entry["pathStateTx"] == "UNSTABLE":
                        edge_unstable += 1;
                    if entry["pathStateTx"] == "INITIAL":
                        edge_init += 1;
                    if entry["pathStateTx"] == "DEAD":
                        edge_dead += 1;
                    if entry["pathStateTx"] == "UNUSABLE":
                        edge_unusable += 1;
                    if entry["pathStateTx"] == "QUIET":
                        edge_quiet += 1;
                    if entry["pathStateTx"] == "MEASURING_TX_BW":
                        edge_measuring += 1;
                    if entry["pathStateTx"] == "BW_UNMEASURABLE":
                        edge_unmeasurable += 1;
                    if entry["pathStateTx"] == "WAITING_FOR_LINK_BW":
                        edge_waiting += 1;
                    if entry["dynamic"] == "Yes":
                        edge_dynamic += 1;
                    else:
                        edge_static += 1;
                else:
                    gw_total += 1;
                    if peer_name != path["peer_name"]:
                        peer_name = path["peer_name"];
                        peer_gw += 1;
                    if entry["pathStateTx"] == "STABLE" and entry["pathStateRx"] == "STABLE":
                        gw_stable += 1;
                    if entry["pathStateTx"] == "UNSTABLE":
                        gw_unstable += 1;
                    if entry["pathStateTx"] == "INITIAL":
                        gw_init += 1;
                    if entry["pathStateTx"] == "DEAD":
                        gw_dead += 1;
                    if entry["pathStateTx"] == "UNUSABLE":
                        gw_unusable += 1;
                    if entry["pathStateTx"] == "QUIET":
                        gw_quiet += 1;
                    if entry["pathStateTx"] == "MEASURING_TX_BW":
                        gw_measuring += 1;
                    if entry["pathStateTx"] == "BW_UNMEASURABLE":
                        gw_unmeasurable += 1;
                    if entry["pathStateTx"] == "WAITING_FOR_LINK_BW":
                        gw_waiting += 1;

        if namespace.verbose:
            #Automation Friendly format
            edge = { "peer_type":"EDGE", "peer_count":peer_edges, "stable":edge_stable,
                     "unstable":edge_unstable, "initial":edge_init, "dead":edge_dead,
                     "unusable":edge_unusable, "quiet":edge_quiet, "measuring":edge_measuring,
                     "bw_unmeasurable":edge_unmeasurable, "waiting_for_link_bw":edge_waiting,
                     "total_paths":edge_total, "total_dynamic":edge_dynamic, "total_static":edge_static }

            gw = { "peer_type":"GATEWAY", "peer_count":peer_gw, "stable":gw_stable,
                   "unstable":gw_unstable, "initial":gw_init, "dead":gw_dead,
                   "unusable":gw_unusable, "quiet":gw_quiet, "measuring":gw_measuring,
                   "bw_unmeasurable": gw_unmeasurable, "waiting_for_link_bw":gw_waiting,
                   "total_paths":gw_total, "total_dynamic":"0", "total_static":gw_total }
            print(json.dumps([edge,gw], sort_keys = True, indent = 2))
        else:
            output.append(["PEER TYPE", "PEER_COUNT", "STABLE", "UNSTABLE", "INITIAL", "DEAD",
                           "UNUSABLE", "QUIET", "MEASURING", "BW_UNMEASURABLE",
                           "WAITING_FOR_LINK_BW", "TOTAL_PATHS", "TOTAL_DYNAMIC", "TOTAL_STATIC"])
            output.append(["EDGE", str(peer_edges), str(edge_stable), str(edge_unstable),
                           str(edge_init), str(edge_dead), str(edge_unusable), str(edge_quiet),
                           str(edge_measuring), str(edge_unmeasurable), str(edge_waiting),
                           str(edge_total), str(edge_dynamic), str(edge_static)])
            output.append(["GATEWAY", str(peer_gw), str(gw_stable), str(gw_unstable),
                           str(gw_init), str(gw_dead), str(gw_unusable), str(gw_quiet),
                           str(gw_measuring), str(gw_unmeasurable), str(gw_waiting),
                           str(gw_total), "0", str(gw_total)])
            pretty_print_table(output)



class subPathStatsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (values):
            params = {"peer": values}
        else:
            params = {"peer":"all"}
        reply = remote_server.subPathStatsDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["Interface","COS ID" , "PeerName", "PublicIpAddr", "PeerIpAddr", "Version","Path State" ,"RxState", "TxState", "AvgLatencyRx", "AvgLatencyTx", "RxJitter",
                       "TxJitter", "lossRx", "lossTx", "Precedence", "COS Name"])
        for entry in reply:
            if "path" in entry:
                path = entry["path"]
                vlan_id = "NONE";
                priority = "NONE";
                if entry["cosPrecedenceStrict"] == 1:
                    precedence = "STRICT"
                else:
                    precedence = "LOOSE"
                if entry["vlanId"] != 0:
                    vlan_id = str(entry["vlanId"])
                    priority = format(entry["prio8021P"], '03b')
                output.append([path["interface"],str(entry["cos_idx"]) , path["peer_name"], path["ipAddress"], path["gateway"],
                               str(path["version"]), entry["pathState"] ,entry["pathStateRx"],
                               entry["pathStateTx"], str(entry["avgLatencyRx"]),
                               str(entry["avgLatencyTx"]), str(round(entry["jitterRx"], 1)),
                               str(round(entry["jitterTx"], 1)),str(round(entry["lossRx"], 2)),
                               str(round(entry["lossTx"], 2)), precedence, entry["cosName"]])
            else:
                print(json.dumps(reply, sort_keys = True, indent = 2))
                return
        pretty_print_table(output)

class tunnelCountsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"tunnel_counts", "logical_id": values[0]}
        reply = remote_server.tunnelCountsDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class linkStatsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"link_stats", "debug_dump":1, "mode":"up", "ipversion": 0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type param [v4 | v6 | all] [up | all]")
                return
            if len(values) == 2:
                if values[1] == "up" or values[1] == "all":
                    params.update({"mode":values[1]})
                else:
                    print("Invalid link param [v4 | v6 | all] [up | all]")
                    return

        reply = remote_server.linkStatsDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        link_stats = []
        link_stats.append(["Name", "Interface", "Overlay", "VLAN", "prio8021P", "Mode", "Type", "MTU", "Backup", "LocalIpAddr", "PublicIpAddr", "LogicalId", "InternalLogicalId","LinkMode", "State", "VPN State", "bandwidthKbpsTx", "bandwidthKbpsRx", "BytesTx", "BytesRx"])
        for entry in reply:
            if "interface" in entry:
                vlan_id = "NONE";
                priority = "NONE";
                if entry["nonPreferredLink"] == 1 and entry["vpnState"] == "DEAD":
                    continue;
                if entry["vlanId"] != 0:
                    vlan_id = str(entry["vlanId"])
                    priority = format(entry["prio8021P"], '03b')
                backup = "FALSE"
                if entry["backupOnly"] == 1:
                    backup = "TRUE"
                bytesTx = entry["controlBytesTx"] + entry["p1BytesTx"] + entry["p2BytesTx"] + entry["p3BytesTx"]
                bytesRx = entry["controlBytesRx"] + entry["p1BytesRx"] + entry["p2BytesRx"] + entry["p3BytesRx"]
                link_stats.append([entry["name"], entry["interface"],
                    entry["ifaceOverlay"], vlan_id, priority, entry["mode"],
                           entry["type"], str(entry["mtu"]), backup,
                           entry["localIpAddress"], entry["publicIpAddress"],
                           entry["logicalId"], entry["internalId"],entry["linkmode"],
                           entry["state"], entry["vpnState"], str(entry["bpsOfBestPathTx"]/1000),
                           str(entry["bpsOfBestPathRx"]/1000), str(bytesTx), str(bytesRx)])
            else:
                print(json.dumps(reply, sort_keys = True, indent = 2))
                return
        pretty_print_table(link_stats)

class linkCosAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"link_cos_dump"}
        reply = remote_server.linkCosDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        cos_cfg = []
        cos_cfg.append(["Interface", "|", "CoS Name", "|", "DSCPTags", "|", "BwPct", "|", "Bw_Upperlimit", "|", "DefaultCoS"])
        for entry in reply:
            if "interface" in entry:
                cos_cfg.append([entry["interface"], "|", entry["cosName"], "|", entry["dscpTags"], "|", str(entry["bwPct"]), "|", entry["bwUpperlimit"], "|", entry["default"]])
            else:
                print(json.dumps(reply, sort_keys = True, indent = 2))
                return
        pretty_print_table(cos_cfg)

class verboseArpDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"debug":"arp", "count":int(values[0])}
        else:
            params = {"debug":"arp", "count": 0}
        reply = remote_server.arpTableDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class verboseNd6DumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"debug":"nd6", "count":int(values[0])}
        else:
            params = {"debug":"nd6", "count":0}
        reply = remote_server.nd6TableDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ArpDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"debug": "arp", "count": int(values[0])}
        else:
            params = {"debug":"arp", "count": 0}
        reply = remote_server.arpTableDebugDump(**params)

        if namespace.verbose:
          print(json.dumps(reply, sort_keys = True, indent = 2))
          return

        arp = []
        arp.append(["Interface", "Address", "C-Tag", "Flags", "Mac", "S-Tag", "Source Mac",
                   "State", "Refcnt", "Age (in seconds)"])
        for entry in reply:
            arptbl = entry["table"]
            for interface in arptbl:
                arp.append([entry["interface"], interface["address"], str(interface["c-tag"]),
                           str(interface["flags"]), interface["mac"], str(interface["s-tag"]),
                           interface["srcMac"], interface["state"], str(interface["refcnt"]),
                           str((interface["age"] // 1000))])
        pretty_print_table(arp)

class Nd6DumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"debug":"nd6", "count":int(values[0])}
        else:
            params = {"debug":"nd6", "count": 0}
        reply = remote_server.nd6TableDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        nd = []
        nd.append(["Interface", "Address", "C-Tag", "S-Tag", "Mac", "State",
                   "Router", "Queue", "Age(Sec)", "Last Rcv(Sec)", "Refcnt"])
        for entry in reply:
            ndtbl = entry["cache_entry"]
            for interface in ndtbl:
                nd.append([entry["interface"], interface["addr"], str(interface["ctag"]),
                str(interface["stag"]), interface["mac"], interface["state"],
                interface["is_router"], str(interface["icmp_count"]),
                str(interface["age"]), str(interface["last_pkt_rcv"]), str(interface["refcnt"])])
        pretty_print_table(nd)


class ClearArpCache(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"clear_arp_cache":values[0]}
        reply = remote_server.arpCacheClear(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ClearND6Cache(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"clear_nd6_cache":values[0]}
        reply = remote_server.nd6CacheClear(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class memoryLeak(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"MB_to_leak":int(values[0])}
        reply = remote_server.memoryLeak(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class decAction(argparse.Action):
    def get_dec_color(self, red, red_pending, yellow, yellow_pending):
        if red:
            if red_pending:
                return "red*"
            else:
                return "red"
        elif yellow:
            if yellow_pending:
                return "yellow*"
            else:
                return "yellow"
        return "green"

    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dec"}
        reply = remote_server.decDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        dec_stats = []
        dec_stats.append(["Element", "|", "Dest", "|", "Dest", "|", "Subpath" , "|", "Mode"  ,  "|", "LATENCY", "LATENCY", "LATENCY", "LATENCY", "|", "JITTER", "JITTER", "JITTER", "JITTER", "|", "LOSS", "LOSS", "LOSS", "LOSS"])
        dec_stats.append(["Name", "|", "Name", "|", "Ip", "|", "COS ID" , "|", "Mode", "|", "ms", "VOICE", "VIDEO", "TRANS", "|", "ms", "VOICE", "VIDEO", "TRANS",   "|", "PCT", "VOICE", "VIDEO", "TRANS"])
        for entry in reply:
            if "interface" in entry:
                dec_stats.append([entry["interface"], "|", entry["destName"], "|",
                    entry["destIp"], "|", entry["subPath"], "|", entry["mode"], "|",
                #latency flags
                str(entry["bestLatencyMs"]),
                self.get_dec_color(entry["voiceLatencyRed"], entry["voiceLatencyRedPending"], entry["voiceLatencyYellow"], entry["voiceLatencyYellowPending"]),
                self.get_dec_color(entry["videoLatencyRed"], entry["videoLatencyRedPending"], entry["videoLatencyYellow"], entry["videoLatencyYellowPending"]),
                self.get_dec_color(entry["transLatencyRed"], entry["transLatencyRedPending"], entry["transLatencyYellow"], entry["transLatencyYellowPending"]),
                "|",
                #jitter flags
                str(entry["bestJitterMs"]),
                self.get_dec_color(entry["voiceJitterRed"], entry["voiceJitterRedPending"], entry["voiceJitterYellow"], entry["voiceJitterYellowPending"]),
                self.get_dec_color(entry["videoJitterRed"], entry["videoJitterRedPending"], entry["videoJitterYellow"], entry["videoJitterYellowPending"]),
                self.get_dec_color(entry["transJitterRed"], entry["transJitterRedPending"], entry["transJitterYellow"], entry["transJitterYellowPending"]),
                "|",
                #loss flags
                str(round(entry["bestLossPct"], 3)),
                self.get_dec_color(entry["voiceLossRed"], entry["voiceLossRedPending"], entry["voiceLossYellow"], entry["voiceLossYellowPending"]),
                self.get_dec_color(entry["videoLossRed"], entry["videoLossRedPending"], entry["videoLossYellow"], entry["videoLossYellowPending"]),
                self.get_dec_color(entry["transLossRed"], entry["transLossRedPending"], entry["transLossYellow"], entry["transLossYellowPending"])])
            else:
                print(json.dumps(reply, sort_keys = True, indent = 2))
                return
        pretty_print_table(dec_stats)
        print("* indicates state pending transition")

class qoeThresholdAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"qoe_threshold"}
        reply = remote_server.qoeThresholdDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class chatStatsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {
            "debug": "chat_stats",
            "sip": "all",
            "dip": "all",
            "dport": "all",
            "timeout_ms": get_timeout_ms(namespace) // 10,
            "limit": get_entry_limit(namespace),
            "app_id": "all",
            "pretty_file_name": None
        }
        if values is not None:
            for value in values:
                if "=" not in value:
                    print(f"Invalid filter format: {value}. Use 'key=value'.")
                    return
                key, val = value.split("=", 1)
                if key not in ["sip", "dip", "dport", "app_id", "pretty_file_name"]:
                    print((f"Invalid filter key: {key}. Allowed keys are 'sip',"
                            "'dip', 'dport', 'app_id', 'pretty_file_name'."))
                    return
                params[key] = val

        reply = remote_server.chatStatsDebugDump(**params)
        truncated = reply["truncated"]
        reply = reply["stats"]
        print(json.dumps(reply, sort_keys = True, indent = 2))
        notify_truncated_output(truncated)

        if params["pretty_file_name"] is not None:
            with open(params["pretty_file_name"], 'w') as file:
                pretty_print_current_apps(reply, file)

class appChatStatsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {
            "debug": "chat_stats",
            "sip": "all",
            "dip": "all",
            "dport": "all",
            "timeout_ms": get_timeout_ms(namespace) // 10,
            "limit": get_entry_limit(namespace),
            "app_id": values[0]
        }
        reply = remote_server.chatStatsDebugDump(**params)
        truncated = reply["truncated"]
        reply = reply["stats"]
        print(json.dumps(reply, sort_keys = True, indent = 2))
        notify_truncated_output(truncated)


class diagTriggerAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"traceType":"TRACE-GENERIC"}
        reply = remote_server.diagTrigger(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class qosOverrideAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"override":values[0]}
        reply = remote_server.qosOverride(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class bwTestAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"interface":values[0]}
        reply = remote_server.bwTest(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class linkBwTestAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"link":values[0]}
        reply = remote_server.linkBwTest(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class bwRetestAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"bw_retest"}
        reply = remote_server.bwRetest(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class rxBwCapAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        valid_interfaces=WAN_LINKS
        if values[0] not in valid_interfaces:
            raise ValueError('invalid interface {s!r}'.format(s=values[0]))
        params = {"interface":values[0], "cap_kbps":int(values[1])}
        reply = remote_server.rxBwCap(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class bwTestDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"bw_test_dump"}
        reply = remote_server.bwTestDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class edgeRouteSummary(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (len(values) == 1):
            params = {"segid": values[0]}
        else:
            params = {"segid":"all"}
        reply = remote_server.edgeRouteSummaryDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class userRouteDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 4):
                params = {"segid": values[0], "ip_fam": values[1],
                        "prefix": values[2], "all_or_pref": values[3]}
            if (len(values) == 3):
                params = {"segid": values[0], "ip_fam": values[1],
                        "prefix": values[2], "all_or_pref": "all"}
            if (len(values) == 2):
                params = {"segid": values[0], "ip_fam": values[1],
                        "prefix": "all", "all_or_pref": "all"}
            elif (len(values) == 1):
                params = {"segid": values[0], "ip_fam": "all",
                        "prefix": "all", "all_or_pref": "all"}
        else:
            params = {"segid": "all", "ip_fam": "all", "prefix": "all",
                    "all_or_pref": "all"}

        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace), "logfile": LOGFILE})
        reply = remote_server.userRouteDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class userPeerDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"peers"}
        reply = remote_server.userPeerDump(**params)

        if "Error" in reply or namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        mapping = [('LOGICAL_ID', 'logicalId'), ('PEER', 'peer')]

        pretty_print_table([row for row in json_table_generator(reply, mapping)])

class userPathDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 3:
            params = {"peer":values[0], "sub_path": int(values[1]),
                                        "show_only_hub_cluster_ic_tun": int(values[2])}
        elif len(values) == 2:
            params = {"peer":values[0], "sub_path": int(values[1]),
                                        "show_only_hub_cluster_ic_tun": 0}
        else:
            params = {"peer":values[0], "sub_path": 0, "show_only_hub_cluster_ic_tun": 0}
        params.update({"logfile": LOGFILE})

        reply = remote_server.userPathDump(**params)

        if "Error" in reply or namespace.verbose or LOGFILE != "NIL":
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        mapping = [
            ('PEER','peer'),
            ('LINK','link'),
            ('LOCAL_IP','localPublicIP'),
            ('PEER_IP','peerPublicIP'),
            ('Kbps_RX','bandwidthKbpsRx'),
            ('Kbps_TX','bandwidthKbpsTx'),
            ('AVG_LAT_RX','avgLatencyRx'),
            ('AVG_LAT_TX','avgLatencyTx'),
            ('JITTER_RX','jitterRx'),
            ('JITTER_TX','jitterTx'),
            ('LOSS_RX','lossRx'),
            ('LOSS_TX','lossTx'),
            ('PACKETS_RX','packetsRx'),
            ('PACKETS_TX','packetsTx'),
            ('BYTES_RX','bytesRx', bytes_formatter),
            ('BYTES_TX','bytesTx', bytes_formatter),
            ('DYNAMIC','isdynamic', bool_formatter),
            ('PATH_UPTIME','pathUpMs', millisecs_formatter),
            ('STATE','state'),
            ('STRICT','strictIpPrecedence'),
            ('VPN_STATE','vpnState')
        ]

        pretty_print_table([row for row in json_table_generator(reply, mapping)])

class userFlowDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):

        if len(values) > 7:
            print("""Unexpected No. of arguments are provided.
                  usage: --user_flow_dump [all | seg-id] [all | src-ip] [all | src-port]
                       [all | dest-ip] [all | dest-port] [max flows to display] [all | v4 | v6]""")
            return

        params = {"seg": get_value(values, 0, 'all'), "sip": get_value(values, 1, 'all'),
                  "sport": get_value(values, 2, 'all'), "dip": get_value(values, 3, 'all'),
                  "dport": get_value(values, 4, 'all'), "count": get_value(values, 5, 'all'),
                  "family": get_value(values, 6, 'all'), "fw": 0}
        if params["family"] not in ['v4', 'v6', 'all']:
            params["family"] = 'all'

        reply = remote_server.userFlowDump(**params)

        if "Error" in reply or namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        flows = reply['flows']
        mapping = [('SRC_IP', 'srcIP'), ('DEST_IP', 'destIP'),
            ('SRC_PORT', 'srcPort', port_formatter), ('DEST_PORT', 'destPort', port_formatter),
            ('PROTO', 'proto', proto_str), ('DSCP', 'dscp'), ('APP', 'appProtoString'),
            ('IDLE_TIME', 'idleTimeMs', millisecs_formatter),
            ('AGE', 'ageMs', millisecs_formatter),
            ('TCP_RTT_MS', 'tcpRttMs', millisecs_formatter)]

        pretty_print_table([row for row in json_table_generator(flows, mapping)])

class userFirewallDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):

        if len(values) > 9:
            print("""Unexpected No.of arguments are provided.
                usage: --user_firewall_dump [all | seg-id] [all | src-ip] [all | src-port]
                    [all | dest-ip] [all | dest-port] [max flows to display] [all | v4 | v6]
                    [efs-rule] [allow | block]""")
            return

        params = {"seg": get_value(values, 0, 'all'), "sip": get_value(values, 1, 'all'),
                "sport": get_value(values, 2, 'all'), "dip": get_value(values, 3, 'all'),
                "dport": get_value(values, 4, 'all'), "count": get_value(values, 5, 'all'),
                "family": get_value(values, 6, 'all'), "efs_rule": get_value(values, 7, 'all'),
                "efs_action": get_value(values, 8, 'allow'), "fw": 1}
        if params["family"] not in ['v4', 'v6', 'all']:
            params["family"] = 'all'

        reply = remote_server.userFlowDump(**params)

        if "Error" in reply or namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        flows = reply['flows']
        mapping = [('SRC_IP', 'srcIP'), ('DEST_IP', 'destIP'),
            ('SRC_PORT', 'srcPort', port_formatter), ('DEST_PORT', 'destPort', port_formatter),
            ('PROTO', 'proto', proto_str), ('DSCP', 'dscp'), ('APP', 'appProtoString'),
            ('TCP_STATE', 'tcpState'), ('RULE', 'fwPolicy'),
            ('BYTES_SENT', 'bytesSent', bytes_formatter),
            ('BYTES_RCVD', 'bytesRcvd', bytes_formatter),
            ('DURATION', 'sessionDurationSecs', seconds_formatter),
            ('LAN_SIDE_NAT', 'lanSideNatType'), ('NAT_SIP', 'natSrcIp'),
            ('NAT_SPORT', 'natSrcPort', port_formatter),
            ('NAT_DIP', 'natDstIp'), ('NAT_DPORT', 'natDstPort', port_formatter),
            ('EFS_ACTION', 'efsAction'),
            ('IDPS_ACTION', 'idpsAction'), ('SIGNATURE_ID', 'idpsSignature', port_formatter),
            ('SEVERITY', 'idpsSeverity', port_formatter),
            ('URL_REP', 'urlReputation'), ('URL_REP_ACTION', 'urlRepAction'),
            ('URL_CAT', 'urlCategory'), ('URL_CAT_ACTION', 'urlCatAction'),
            ('MAL_IP_ACTION', 'malIpAction')]

        pretty_print_table([row for row in json_table_generator(flows, mapping)])

class userFlowFlushAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"sip": values[0], "dip": values[1]}
        reply = remote_server.userFlowFlush(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class userFirewallFlushAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"sip": values[0], "dip": values[1]}
        reply = remote_server.userFirewallFlush(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class bizPnatOneToOneDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"one_to_one_nat","segid":"all","ipversion":0}
        segopt = "all"
        if len(values) > 1:
            if values[1] == "v4":
                params.update({"ipversion":4})
            elif values[1] == "v6":
                params.update({"ipversion":6})
            elif values[1] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        if len(values) > 0:
            segopt = values[0]
            params.update({"segid":segopt})

        reply = remote_server.bizOneToOneNatDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        seg_rules = []
        seg_rules.append(["Segment", "Destination Id", "Match IP", "NAT IP", "Prefix"])
        for sr in reply:
            seg_str = str(sr["seg"])
            if segopt != "all" and segopt != seg_str:
                continue

            for r in sr["Rules"]:
                if "Rules" in r:
                    for rr in sr["Rules"]["Rules"]:
                        seg_rules.append([seg_str, rr["dest_id"], rr["match_ip"], rr["nat_ip"], str(rr["prefix"])])
        if len(seg_rules) > 1:
            pretty_print_table(seg_rules)

class controlbytes(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"control_type"}
        if len(values) < 1:
            print("Insufficient Arguments;  Please choose 'peer' or 'link'")
            return

        if values and "link" in values:
            params["link"] = 1

        if values and "peer" in values:
            params["peer"] = 1

        if values and "clear" in values:
            params["clear"] = 1

        if values and "all" in values:
            params["all"] = 1

        reply = remote_server.controlbytes(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        for connection in reply:
            print ("\n============================ Control Info for %s %s =================================\n" %(connection["type"],connection["name"]))
            control = []
            if (connection["type"] == "link"):
                control.append(["Link Name", "Control Message Type", "Tx Bytes" , "Tx Packets", "Rx Bytes", "Rx Packets"])
            if(connection["type"] == "peer"):
                control.append(["Peer Name", "Control Message Type", "Tx Bytes" , "Tx Messages", "Rx Bytes", "Rx Messages"])
            for entry in connection["control"]:
                control.append([str(entry["name"]), str(entry["ctrl_msg_type"]), str(entry["Tx_byte"]), str(entry["Tx_num"]), str(entry["Rx_byte"]), str(entry["Rx_num"])])
            pretty_print_table(control)

def pretty_print_routes(reply, file=sys.stdout):
    routes = []
    routes.append(["Address", "Netmask", "Type", "Gateway", "Next Hop Name",
                   "Next Hop ID", "Destination Name", "Dst LogicalId", "Reachable",
                   "Metric", "Preference", "Flags", "Vlan", "Intf", "Sub IntfId",
                   "MTU", "SEG"])
    for entry in reply["routes"]:
        vlan_id = str(entry["vlan_id"])
        if vlan_id == "524287":
            vlan_id = "N/A"
        sub_intf_id = str(entry["sub_intf_id"])
        if sub_intf_id == "-1":
            sub_intf_id = "N/A"
        routes.append([entry["addr"], entry["netmask"], entry["type"], entry["gateway"],
                       entry["nh_name"], entry["nhId"], entry["dest_name"], entry["logicalId"],
                       str(entry["reachable"]), str(entry["metric"]), str(entry["preference"]),
                       str(entry["flags"]), vlan_id, entry["intf"], sub_intf_id, entry["mtu"],
                       str(entry["segment"])])

    pretty_print_table(routes, file)
    legend_str = "P - PG, B - BGP, D - DCE, L - LAN SR, C - Connected, O - External, "\
                 "W - WAN SR, S - SecureEligible, R - Remote, s - self, r - recursive, H - HA, "\
                 "m - Management, n - nonVelocloud, v - ViaVeloCloud, A - RouterAdvertisement, "\
                 "c - CWS, a - RAS, g - Global PG Static, b - Blackhole, I - IPSec, "\
                 "G - GRE, p - Peer\n"
    file.write(legend_str)

def pretty_print_unique_routes(reply, file=sys.stdout):
    routes = []
    routes.append(["Address", "Netmask", "Type", "Gateway", "Next Hop Name",
                   "Next Hop ID", "Destination Name", "Dst LogicalId", "Reachable",
                   "Metric", "Preference", "Flags", "Vlan", "Intf", "Sub IntfId", "MTU", "SEG", "NH Count"])
    for entry in reply["routes"]:
        vlan_id = str(entry["vlan_id"])
        if vlan_id == "524287":
            vlan_id = "N/A"
        sub_intf_id = str(entry["sub_intf_id"])
        if sub_intf_id == "-1":
            sub_intf_id = "N/A"
        routes.append([entry["addr"], entry["netmask"], entry["type"], entry["gateway"],
                       entry["nh_name"], entry["nhId"], entry["dest_name"], entry["logicalId"],
                       str(entry["reachable"]), str(entry["metric"]), str(entry["preference"]),
                       str(entry["flags"]), vlan_id, entry["intf"], sub_intf_id, entry["mtu"],
                       str(entry["segment"]), str(entry["nhcount"])])

    pretty_print_table(routes, file)
    legend_str = "P - PG, B - BGP, D - DCE, L - LAN SR, C - Connected, O - External, "\
                 "W - WAN SR, S - SecureEligible, R - Remote, s - self, r - recursive, H - HA, "\
                 "m - Management, n - nonVelocloud, v - ViaVeloCloud, A - RouterAdvertisement, "\
                 "c - CWS, a - RAS, g - Global PG Static, b - Blackhole, I - IPSec, "\
                 "G - GRE\n"
    file.write(legend_str)

class unifiedRouteDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1": values[0], "arg2": "all", "arg3": "all"}
        elif len(values) == 2:
            params = {"arg1": values[0], "arg2": values[1], "arg3": "all"}
        elif len(values) == 3:
            params = {"arg1": values[0], "arg2": values[1], "arg3": values[2]}
        else:
            params = {"arg1": "all", "arg2": "all", "arg3": "all"}

        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})

        reply = remote_server.unifiedRouteDebugDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        pretty_print_routes(reply)
        notify_truncated_output(truncated)

class uniqueRouteDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1" : values[0], "arg2" : "all", "arg3" : "all"}
        elif len(values) == 2:
            params = {"arg1" : values[0], "arg2" : values[1], "arg3" : "all"}
        elif len(values) == 3:
            params = {"arg1" : values[0], "arg2" : values[1], "arg3" : values[2]}
        else:
            params = {"arg1" : "all" , "arg2" : "all", "arg3" : "all"}
        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})

        reply = remote_server.uniqueRouteDebugDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        pretty_print_unique_routes(reply)
        notify_truncated_output(truncated)


class PeerRouteDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1":values[0]}
        else:
            params = {"arg1":"all"}
        reply = remote_server.PeerRouteDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))


class localRouteDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1":values[0], "arg2":"all", "arg3":"all"}
        elif len(values) == 2:
            params = {"arg1":values[0], "arg2":values[1], "arg3":"all"}
        elif len(values) == 3:
            params = {"arg1":values[0], "arg2":values[1], "arg3":values[2]}
        else:
            params = {"arg1":"all", "arg2":"all", "arg3":"all"}
        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})

        reply = remote_server.localRouteDebugDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        routes = []
        routes.append(["Address", "Netmask", "Type", "Gateway", "Next Hop ID", "Dst LogicalId", "Reachable", "Metric", "Preference", "Flags", "Vlan", "Intf", "MTU", "SEG"])
        for entry in reply["routes"]:
            vlan_id = str(entry["vlan_id"])
            if vlan_id == "524287":
                vlan_id = "N/A"
            routes.append([entry["addr"], entry["netmask"], entry["type"], entry["gateway"], entry["nhId"], entry["logicalId"], str(entry["reachable"]), str(entry["metric"]), str(entry["preference"]), str(entry["flags"]), vlan_id, entry["intf"], entry["mtu"], str(entry["segment"])])
        pretty_print_table(routes)
        legend_str = "P - PG, D - DCE, L - LAN SR, C - Connected, O - External, W - WAN SR, "\
                     "S - SecureEligible, R - Remote, s - self, r - recursive, H - HA, "\
                     "m - Management, n - nonVelocloud, v - ViaVeloCloud, "\
                     "A - RouterAdvertisement, I - IPSec, G - GRE"
        print(legend_str)
        notify_truncated_output(truncated)

class connectedRouteDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1":values[0], "arg2":"all", "arg3": "all"}
        elif len(values) == 2:
            params = {"arg1":values[0], "arg2":values[1], "arg3": "all"}
        elif len(values) == 3:
            params = {"arg1":values[0], "arg2":values[1], "arg3": values[2]}
        else:
            params = {"arg1":"all", "arg2":"all", "arg3": "all"}
        reply = remote_server.connectedRouteDebugDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        routes = []
        routes.append(["Address", "Netmask", "Type", "Gateway", "Next Hop ID", "Dst LogicalId", "Reachable", "Metric", "Preference", "Flags", "Vlan", "Intf", "MTU", "SEG"])
        for entry in reply["routes"]:
            vlan_id = str(entry["vlan_id"])
            if vlan_id == "524287":
                vlan_id = "N/A"
            routes.append([entry["addr"], entry["netmask"], entry["type"], entry["gateway"], entry["nhId"], entry["logicalId"],
                          str(entry["reachable"]), str(entry["metric"]), str(entry["preference"]), str(entry["flags"]),
                          vlan_id, entry["intf"], entry["mtu"], str(entry["segment"])])
        pretty_print_table(routes)
        print("P - PG, D - DCE, L - LAN SR, C - Connected, O - External, W - WAN SR, "\
              "S - SecureEligible, R - Remote, s - self, "\
              "H - HA, m - Management, v - ViaVeloCloud, A - RouterAdvertisement")

class overlayRouteDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1":values[0], "arg2":"all", "arg3":"all"}
        elif len(values) == 2:
            params = {"arg1":values[0],"arg2":values[1], "arg3":"all"}
        elif len(values) == 3:
            params = {"arg1":values[0],"arg2":values[1], "arg3":values[2]}
        else:
            params = {"arg1":"all","arg2":"all","arg3":"all"}
        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})
        reply = remote_server.overlayRouteDebugDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        routes = []
        routes.append(["Address", "Netmask", "Type", "Gateway", "Next Hop ID", "Dst LogicalId", "Reachable", "Metric", "Preference", "Flags", "Vlan", "Intf", "MTU", "SEG"])
        for entry in reply["routes"]:
            vlan_id = str(entry["vlan_id"])
            if vlan_id == "524287":
                vlan_id = "N/A"
            routes.append([entry["addr"], entry["netmask"], entry["type"], entry["gateway"], entry["nhId"], entry["logicalId"], str(entry["reachable"]), str(entry["metric"]), str(entry["preference"]), str(entry["flags"]), vlan_id, entry["intf"], entry["mtu"], str(entry["segment"])])
        pretty_print_table(routes)
        legend_str = "P - PG, D - DCE, L - LAN SR, C - Connected, O - External, W - WAN SR, "\
                     "S - SecureEligible, R - Remote, s - self, r - recursive, H - HA, "\
                     "m - Management, v - ViaVeloCloud, A - RouterAdvertisement, "\
                     "c - CWS, a - RAS"
        print(legend_str)
        notify_truncated_output(truncated)

class remoteRouteDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1":values[0], "arg2":"all", "arg3":"all", "arg4":"all"}
        elif len(values) == 2:
            params = {"arg1":values[0],"arg2":values[1], "arg3":"all", "arg4":"all"}
        elif len(values) == 3:
            params = {"arg1":values[0],"arg2":values[1], "arg3":values[2], "arg4":"all"}
        elif len(values) == 4:
            params = {"arg1":values[0],"arg2":values[1], "arg3":values[2], "arg4":values[3]}
        else:
            params = {"arg1":"all","arg2":"all","arg3":"all","arg4":"all"}

        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})

        reply = remote_server.remoteRouteDebugDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        routes = []
        routes.append(["Address", "Netmask", "Type", "Gateway", "Next Hop ID", "Dst LogicalId","Metric", "Preference", "Flags", "Vlan", "Intf", "MTU", "SEG"])
        for entry in reply["routes"]:
            vlan_id = str(entry["vlan_id"])
            if vlan_id == "524287":
                vlan_id = "N/A"
            routes.append([entry["addr"], entry["netmask"], entry["type"], entry["gateway"], entry["nhId"], entry["logicalId"], str(entry["metric"]), str(entry["preference"]), str(entry["flags"]), vlan_id, entry["intf"], entry["mtu"], str(entry["segment"])])
        pretty_print_table(routes)
        legend_str = "P - PG, D - DCE, L - LAN SR, C - Connected, O - External, W - WAN SR, "\
                     "S - SecureEligible, R - Remote, s - self, r - recursive, H - HA, "\
                     "m - Management, v - ViaVeloCloud, A - RouterAdvertisement, "\
                     "c - CWS, a - RAS"
        print(legend_str)
        notify_truncated_output(truncated)

class datacenterRouteDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1":values[0], "arg2":"all"}
        elif len(values) == 2:
            params = {"arg1":values[0],"arg2":values[1]}
        else:
            params = {"arg1":"all","arg2":"all"}
        reply = remote_server.datacenterRouteDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        routes = []
        routes.append(["Address", "Netmask", "Type", "Gateway", "Next Hop ID", "Dst LogicalId", "Reachable", "Metric", "Preference", "Flags", "Vlan", "Intf", "MTU"])
        for entry in reply["routes"]:
            vlan_id = str(entry["vlan_id"])
            if vlan_id == "524287":
                vlan_id = "N/A"
            routes.append([entry["addr"], entry["netmask"], entry["type"], entry["gateway"], entry["nhId"], entry["logicalId"], str(entry["reachable"]), str(entry["metric"]), str(entry["preference"]), str(entry["flags"]), vlan_id, entry["intf"], entry["mtu"]])
        pretty_print_table(routes)
        legend_str = "P - PG, D - DCE, L - LAN SR, C - Connected, O - External, W - WAN SR, "\
                     "S - SecureEligible, R - Remote, s - self, r - recursive, H - HA, "\
                     "m - Management, n - nonVelocloud, v - ViaVeloCloud, "\
                     "A - RouterAdvertisement, c - CWS, a - RAS, "\
                     "I - IPSec, G - GRE"
        print(legend_str)

class nvsLbTableDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {}
        params.update({"debug":"nvsLbTableDump"})
        reply = remote_server.nvsLbTableDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class bgpDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        bgpRunning = subprocess.check_output("vtysh " + "-d bgpd " + "-c \"show running\"",
                                                universal_newlines=True, shell=True)
        if len(bgpRunning) > 0:
                print("show running-config")
                print("===================")
                print(bgpRunning)
        bgpSummaryDump = subprocess.check_output("vtysh " + "-d bgpd " +
                                                "-c \"sh bgp vrf all summary\"",
                                                universal_newlines=True, shell=True)
        if len(bgpSummaryDump) > 0:
                print("sh bgp vrf all summary")
                print("===================")
                print(bgpSummaryDump)
        bgpNbrDump = subprocess.check_output("vtysh " + "-d bgpd " +
                                                "-c \"sh bgp vrf all neighbors\"",
                                                universal_newlines=True, shell=True)
        if len(bgpNbrDump) > 0:
                print("sh bgp vrf all neighbors")
                print("===================")
                print(bgpNbrDump)
        bgpDump = subprocess.check_output("vtysh " + "-d bgpd " + "-c \"show ip bgp vrf all\"",
                                                universal_newlines=True, shell=True)
        if len(bgpDump) > 0:
                print("show ip bgp vrf all")
                print("===================")
                print(bgpDump)
        bgp6Dump = subprocess.check_output("vtysh " + "-d bgpd " + "-c \"show bgp vrf all ipv6\"",
                                                universal_newlines=True, shell=True)
        if len(bgp6Dump) > 0:
                print("show bgp vrf all ipv6")
                print("===================")
                print(bgp6Dump)
        for line in bgpSummaryDump.split('\n'):
            if line.startswith("BGP view name "):
                curr_segment = line[14:].strip()
                bgpIpViewDump = subprocess.check_output("vtysh " + "-d bgpd " +
                                                "-c \"show ip bgp view " + curr_segment + "\"",
                                                universal_newlines=True, shell=True)
                if len(bgpIpViewDump) > 0:
                    print("BGP View for segment ID: " + curr_segment)
                    print("===========================")
                    print(bgpIpViewDump)
                bgpOutput = subprocess.check_output("ip netns exec " +
                                                curr_segment + " ifconfig -a",
                                                universal_newlines=True, shell=True)
                if len(bgpOutput) > 0:
                    print("NS interface list for segment ID: " + curr_segment)
                    print("====================================")
                    print(bgpOutput)
                bgpOutput = subprocess.check_output("ip netns exec " + curr_segment + " route -n",
                                                universal_newlines=True, shell=True)
                if len(bgpOutput) > 0:
                    print("NS route list for segment ID: " + curr_segment)
                    print("================================")
                    print(bgpOutput)
                bgpOutput = subprocess.check_output("ip netns exec " + curr_segment +
                                                " route -A inet6",
                                                universal_newlines=True, shell=True)
                if len(bgpOutput) > 0:
                    print("NS IPv6 route list for segment ID: " + curr_segment)
                    print("================================")
                    print(bgpOutput)
                bgpOutput = subprocess.check_output("ip netns exec " + curr_segment +
                                                " netstat -natp",
                                                universal_newlines=True, shell=True)
                if len(bgpOutput) > 0:
                    print("NS netstat dump for segment ID: " + curr_segment)
                    print("==================================")
                    print(bgpOutput)

class bgpInfoDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "segment": "all" }
        if len(values) == 1:
            params = { "segment": values[0] }
        params.update({ "timeout_ms": get_timeout_ms(namespace) // 10 })
        reply = remote_server.bgpInfoDump(**params)
        bgp = reply["bgp"]
        truncated = reply["truncated"]
        print(json.dumps(bgp, sort_keys = True, indent = 2))
        notify_truncated_output(truncated)

class bfdDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        bfdRunning = subprocess.check_output("vtysh " + "-d bfdd " + "-c  \"show running\"",
                                                universal_newlines=True, shell=True)
        if len(bfdRunning) > 0:
            print("show running-config")
            print("===================")
            print(bfdRunning)
        bfdSummaryDump = subprocess.check_output("vtysh " + "-d bfdd " + "-c \"sh bfd peers\"",
                                                universal_newlines=True, shell=True)
        if len(bfdSummaryDump) > 0:
            print("sh bfd peers")
            print("============")
            print(bfdSummaryDump)
        bfdCounterDump = subprocess.check_output("vtysh " + "-d bfdd " +
                                                "-c \"show bfd peers counters\"",
                                                universal_newlines=True, shell=True)
        if len(bfdCounterDump) > 0:
            print("sh bfd peers counters")
            print("=====================")
            print(bfdCounterDump)

class bfdDumpInfo(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 2):
                params = {"seg": values[0], "ip_fam": values[1]}
            elif (len(values) == 1):
                params = {"seg": values[0], "ip_fam": "all"}
        else:
            params = {"seg": "all", "ip_fam": "all"}
        bfdSummaryDump = subprocess.check_output("vtysh " + "-d bfdd " +
                                                "-c \"sh bfd peers json\"",
                                                universal_newlines=True, shell=True)
        if len(bfdSummaryDump) <= 0:
            return
        frrJson = json.loads(bfdSummaryDump)

        edgedJson = []
        edgedIndex = 0
        for i in range(len(frrJson)):
            # the vrf name is [vc:segId:2]
            split_vrf = (frrJson[i]['vrf']).split(':')

            # FRR doesn't have cmd to show peers based on af.
            af = ""
            if ":" in frrJson[i]['peer']:
                af = "v6"
            else:
                af = "v4"
            if ((params['seg'] == 'all') or (params['seg'] == split_vrf[1])) and \
                ((params['ip_fam'] == 'all') or (params['ip_fam'] == af)):
                edgedJson.append({'detectMultiplier': frrJson[i]['detect-multiplier'],
                      'localAddress': frrJson[i]['local'],
                      'multiHop': frrJson[i]['multihop'],
                      'peerAddress': frrJson[i]['peer'],
                      'receiveInterval': frrJson[i]['receive-interval'],
                      'segId': int(split_vrf[1]),
                      'state': (frrJson[i]['status']).upper(),
                      'transmitInterval': frrJson[i]['transmit-interval'],
                      'upDownTime': str(datetime.timedelta(seconds = 0))})

                # when up/down only time is provided by FRR.
                if 'uptime' in list(frrJson[i].keys()):
                    edgedJson[edgedIndex]['upDownTime'] = \
                        str(datetime.timedelta(seconds = frrJson[i]['uptime']))
                if 'downtime' in list(frrJson[i].keys()):
                      edgedJson[edgedIndex]['upDownTime'] = \
                        str(datetime.timedelta(seconds = frrJson[i]['downtime']))

                edgedIndex += 1

        edgedJson.sort(key = lambda x:x['segId'])
        reply = {}
        reply['peers'] = edgedJson
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        peers = []
        peers.append(["Peer Address", "Local Address", "Segment Id", "Detect Multiplier",
                     "Transmit Interval", "Receive Interval", "Multihop", "State", "Up/Down Time"])
        for entry in reply["peers"]:
            peers.append([entry["peerAddress"], entry["localAddress"],str(entry["segId"]),
                         str(entry["detectMultiplier"]),str(entry["transmitInterval"]),
                         str(entry["receiveInterval"]),str(entry["multiHop"]), entry["state"],
                         entry["upDownTime"]])
        pretty_print_table(peers)

class raViewDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):

        params = {"dip":"all", "seg": "all"}
        reply = remote_server.raViewDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        ra_view = []
        ra_view.append(["Address", "Netmask", "Gateway", "Metric", "Preference", "Route Lifetime",
                        "Intf", "Vlan", "Advertise", "Reachable", "SegmentId", "On Link"])
        for entry in reply["ra_view"]:
            ra_view.append([entry["addr"], entry["netmask"], entry["gateway"],
                           str(entry["metric"]),
                           entry["preference"], str(entry["lifetime"]),
                           entry["interface"], str(entry["vlan"]), entry["advertise"],
                           entry["reachable"], entry["segId"], entry["onlink"]])
        pretty_print_table(ra_view)

class updateRAHostConfig(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {
                "interface" : values[0],
                "subif_idx" : int(values[1]),
                "filepath" : values[2]
                }
        reply = remote_server.updateRAHostConfig(**params);
        print(reply)

class raHostConfigDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug" : "raHostConfigDump"}
        reply = remote_server.raHostConfigDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        ra_hc_table = []
        ra_hc_table.append(["Interface", "AcceptMTU", "AcceptDefaultRoutes",
            "AcceptSpecificRoutes", "AcceptTimers"])
        for entry in reply:
            ra_hc_table.append([entry["logical_name"],
                                str(entry["mtu"]),
                                str(entry["defaultRoutes"]),
                                str(entry["specificRoutes"]),
                                str(entry["nd6Timers"])])

        pretty_print_table(ra_hc_table)

class bgpViewDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 3):
                params = {"dip": values[0], "seg": values[1], "ip_fam": values[2]}
            if (len(values) == 2):
                params = {"dip": values[0], "seg": values[1], "ip_fam": "all"}
            elif (len(values) == 1):
                params = {"dip": values[0], "seg": "all", "ip_fam": "all"}
        else:
            params = {"dip": "all", "seg": "all", "ip_fam": "all"}
        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})

        reply = remote_server.bgpViewDump(**params)
        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        bgp_view = []
        bgp_view.append(["Address", "Netmask", "Gateway", "Nbr IP", "Nbr ID", "Metric", "Type",
                        "Intf", "Sync'd", "Advertise", "Inbound", "Preference", "LocalP", "AspL",
                        "Reachable", "Ptr", "Age", "SEG", "Communities"])

        for entry in reply["bgp_view"]:
            bgp_view.append([entry["addr"], entry["netmask"], entry["gateway"], entry["neighbor_ip"],
                            entry["neighbor_id"], str(entry["metric"]), str(entry["metric_type"]),
                            entry["intf"], entry["synced"], entry["advertise"], entry["inbound"],
                            str(entry["preference"]), str(entry["localPreference"]),
                            str(entry["asPathLength"]), entry["reachable"], entry["ptr"],
                            str(entry["age_s"]), entry["segId"], str(entry["communities"])])

        pretty_print_table(bgp_view)
        notify_truncated_output(truncated)

class bgpNeighborSummaryDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (len(values) == 1):
            ip_family = values[0]
        else:
            ip_family = "all"

        if (ip_family == "v4"):
            cmd = "-c \"sh ip bgp vrf all summary\""
        elif (ip_family == "v6"):
            cmd = "-c \"sh bgp vrf all ipv6 summary\""
        else:
            cmd = "-c \"sh bgp vrf all summary\""

        bgpSummaryDump = subprocess.check_output("vtysh " + "-d bgpd " + cmd,
                                                universal_newlines=True, shell=True)

        if len(bgpSummaryDump) > 0:
                print("sh bgp vrf", ip_family, "summary")
                print("======================")
                print(bgpSummaryDump)

def parse_table(columns, output, start_line=1):
    parsed_output = []
    for line_no, line in enumerate(output.splitlines()):
        info = {}
        if line_no >= start_line:
            values = line.split()
            for field, value in zip(columns, values):
                info[field] = value
            parsed_output.append(info)
    return parsed_output

def parse_igmpgrp_table(columns, output, start_line=3):
    parsed_output = []
    for line_no, line in enumerate(output.splitlines()):
        info = {}
        if line_no >= start_line:
            values = line.split()
            for field, value in zip(columns, values):
                info[field] = value
            parsed_output.append(info)
    return parsed_output

'''
Dump all igmp info. This info comes directly from pimd, so there's no rpc here
'''
class igmpDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        igmpDump = subprocess.check_output("vtysh " + "-d pimd " + "-c \"show ip igmp groups\"",
                                                universal_newlines=True,
                                                shell=True)
        if len(igmpDump) > 0 and namespace.verbose:
                columns = ["Interface", "Address", "Group", "Mode", "Timer", "Srcs", "V", "Uptime"]
                print("{")
                print('"Igmp_groups":',
                      json.dumps(parse_igmpgrp_table(columns, igmpDump), indent = 2), ",")
        else:
                print("show ip igmp groups")
                print("==================")
                print(igmpDump)

        igmpDump = subprocess.check_output("vtysh " + "-d pimd " + "-c \"show ip igmp interface\"",
                                                universal_newlines=True, shell=True)
        if len(igmpDump) > 0 and namespace.verbose:
                columns = ["Interface", "State", "Address", "V", "Querier", "QuerierIp",
                            "Query_Timer", "Uptime"]
                print('"Igmp_interface":', json.dumps(parse_table(columns, igmpDump), indent = 2))
                print("}")
        else:
                print("show ip igmp interface")
                print("=====================")
                print(igmpDump)

'''
Dump all info from pimd. This info comes directly from pimd, so there's no rpc here
'''
class pimdDump(argparse.Action):
    def dump_pimd_config(self, config):
        parsed_output = []
        interface_info = {}
        for line_no, line in enumerate(config.splitlines()):
            if line.startswith('ip multicast-routing'):
                print('"Multicast_routing":"enabled",') # TODO: fix this
            elif "ip pim hello" in line:
                values = line.split()
                interface_info["Hello_timer"] = values[3]
            elif line.startswith('ip pim'):
                values = line.split()
                if values[2] == "rp":
                    print('"Rp_address": "' + values[3] + '",')
                    print('"Multicast_group": "' + values[4] + '",')
                elif values[2] == "keep-alive-timer":
                    print('"Keep_alive_timer": "' + values[3] + '",')
                elif values[2] == "join-prune-interval":
                    print('"Join_prune_interval": "' + values[3] + '",')
            elif line.startswith('interface'):
                values = line.split()
                interface_info["Name"] = values[1]
                interface_info["Igmp"] = "disabled"
                interface_info["Pim_sm"] = "disabled"
            elif "ip igmp query-max-response-time" in line:
                values = line.split()
                interface_info["Query_max_response_time"] = values[3]
            elif "ip igmp query-interval" in line:
                values = line.split()
                interface_info["Query_interval"] = values[3]
            elif "ip igmp version" in line:
                values = line.split()
                interface_info["Igmp_version"] = values[3]
            elif "ip igmp" in line:
                values = line.split()
                interface_info["Igmp"] = "enabled"
            elif "ip pim sm" in line:
                values = line.split()
                interface_info["Pim_sm"] = "enabled"
            elif line == "!":
                if "Name" in interface_info:
                    parsed_output.append(interface_info)
                    interface_info = {}
        print('"Interface":', json.dumps(parsed_output, indent = 2))

    def __call__(self, parser, namespace, values, option_string=None):
        pimRunning = subprocess.check_output("vtysh " + "-d pimd " + "-c \"show running\"",
                                                universal_newlines=True, shell=True)
        if len(pimRunning) > 0 and namespace.verbose:
                print("{")
                print('"Pim_running_config": {')
                self.dump_pimd_config(pimRunning)
                print("},")
        else:
                print("show running-config")
                print("===================")
                print(pimRunning)

        pimAssertDump = subprocess.check_output("vtysh " + "-d pimd " +
                                                "-c \"show ip pim assert\"",
                                                universal_newlines=True, shell=True)
        if len(pimAssertDump) > 0 and namespace.verbose:
                columns = ["Interface", "Address", "Source", "Group", "State", "Winner", "Uptime", "Timer"]
                print('"Pim_Assert":',
                      json.dumps(parse_table(columns, pimAssertDump), indent = 2), ",")
        else:
                print("show ip pim assert")
                print("==================")
                print(pimAssertDump)

        pimIntfDump = subprocess.check_output("vtysh " + "-d pimd " +
                                                "-c \"show ip pim interface\"",
                                                universal_newlines=True, shell=True)
        if len(pimIntfDump) > 0 and namespace.verbose:
                columns = ["Interface", "State", "Address", "PIM_Nbrs", "PIM_DR", "FHR"]
                print('"Pim_Interface":',
                      json.dumps(parse_table(columns, pimIntfDump), indent = 2), ",")
        else:
                print("show ip pim interface")
                print("=====================")
                print(pimIntfDump)

        pimNeighborDump = subprocess.check_output("vtysh " + "-d pimd " +
                                                "-c \"show ip pim neighbor\"",
                                                universal_newlines=True, shell=True)
        if len(pimNeighborDump) > 0 and namespace.verbose:
                columns = ["Interface", "Neighbor", "Uptime", "Holdtime", "DR_Pri"]
                print('"Pim_Neighbor":',
                      json.dumps(parse_table(columns, pimNeighborDump), indent = 2), ",")
        else:
                print("show ip pim neighbor")
                print("====================")
                print(pimNeighborDump)

        pimStateDump = subprocess.check_output("vtysh " + "-d pimd " +
                                                "-c \"show ip pim state\"",
                                                universal_newlines=True, shell=True)
        if len(pimStateDump) > 0 and namespace.verbose:
                columns = ["Installed", "Source", "Group", "IIF", "OIL"]
                print('"Pim_State":',
                      json.dumps(parse_table(columns, pimStateDump, start_line = 2),
                                 indent = 2), ",")
        else:
                print("show ip pim state")
                print("=================")
                print(pimStateDump)

        pimRPInfoDump = subprocess.check_output("vtysh " + "-d pimd " +
                                                "-c \"show ip pim rp-info\"",
                                                universal_newlines=True, shell=True)
        if len(pimRPInfoDump) > 0 and namespace.verbose:
                columns = ["Rp_address", "group/prefix-list", "OIF", "RP"]
                print('"Pim_RpInfo":',
                      json.dumps(parse_table(columns, pimRPInfoDump), indent = 2), ",")
        else:
                print("show ip pim rp-info")
                print("===================")
                print(pimRPInfoDump)

        pimRPFDump = subprocess.check_output("vtysh " + "-d pimd " +
                                                "-c \"show ip pim rpf\"",
                                                universal_newlines=True, shell=True)
        if len(pimRPFDump) > 0 and namespace.verbose:
                print('"Pim_Rpf": {')
                for line_no, line in enumerate(pimRPFDump.splitlines()):
                    if line.strip() == '':
                        break
                    values = line.split(":", 1)
                    print('"' + values[0].replace(" ", "_") + '": "' + \
                          values[1].replace(" ", "") + '",')
                columns = ["Source", "Group", "RpfIface", "RpfAddress", "RibNextHop", "Metric", "Pref"]
                print('"RpfInfo":',
                      json.dumps(parse_table(columns, pimRPFDump, start_line = line_no + 2),
                                 indent = 2), "},")
        else:
                print("show ip pim rpf")
                print("===============")
                print(pimRPFDump)

        pimJoinDump = subprocess.check_output("vtysh " + "-d pimd " +
                                                "-c \"show ip pim join\"",
                                                universal_newlines=True, shell=True)
        if len(pimJoinDump) > 0 and namespace.verbose:
                columns = ["Interface", "Address", "Source", "Group", "State", "Uptime", "Expire", "Prune"]
                print('"Pim_Join":', json.dumps(parse_table(columns, pimJoinDump), indent = 2))
                print("}")
        else:
                print("show ip pim join")
                print("================")
                print(pimJoinDump)

'''
Dump neighbor info from pimd. This info comes directly from pimd, so there's no rpc here
'''
class pimNeighborDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        pimNeighborDump = subprocess.check_output("vtysh " + "-d pimd " +
                                                "-c \"show ip pim neighbor\"",
                                                universal_newlines=True, shell=True)
        params = {"debug":"pim_neighbor_dump"}
        reply = remote_server.pimNeighborDump(**params)
        output = []
        output.append(["SegId", "PimInterface", "PeerName"])
        for entry in reply:
            output.append([str(entry['segId']), entry['interface'], entry['peerName']])
        if namespace.verbose:
            print('{\n"Pim_Interface":', json.dumps(reply, indent = 2), ",")
        else:
            pretty_print_table(output)

        if len(pimNeighborDump) > 0 and namespace.verbose:
                columns = ["Interface", "Neighbor", "Uptime", "Holdtime", "DR_Pri"]
                print('"Pim_Neighbor":',
                      json.dumps(parse_table(columns, pimNeighborDump), indent = 2))
                print("}")
        else:
                print("")
                print("show ip pim neighbor")
                print("====================")
                print(pimNeighborDump)

class ospfViewDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 3):
                params = {"dip": values[0], "ip_fam": values[1], "seg": values[2]}
            elif (len(values) == 2):
                 params = {"dip": values[0], "ip_fam": values[1], "seg": "all"}
            elif (len(values) == 1):
                params = {"dip":values[0], "seg": "all", "ip_fam": "all"}
        else:
            params = {"dip": "all", "seg": "all", "ip_fam": "all"}
        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})

        reply = remote_server.ospfViewDump(**params)
        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        ospf_view = []
        ospf_view.append(["Address", "Netmask", "Gateway", "Nbr IP", "Nbr ID", "Metric",
                          "OSPF Cost", "Preference", "Type", "Intf", "Synced", "Advertise",
                          "Inbound", "Tag", "Reachable", "Ptr", "Age", "Seg"])
        for entry in reply["ospf_view"]:
            ospf_view.append([entry["addr"], entry["netmask"], entry["gateway"],
                              entry["neighbor_ip"], entry["neighbor_id"],
                              str(entry["metric"]), str(entry["cost"]),
                              str(entry["preference"]), str(entry["metric_type"]),
                              entry["intf"], entry["synced"], entry["advertise"],
                              entry["inbound"], str(entry["tag"]),
                              entry["reachable"], entry["ptr"],
                              str(entry["age_s"]), entry["segId"]])
        pretty_print_table(ospf_view)
        print("O - Intra Area, IA - Inter Area, OE1 - External 1, OE2 - External 2")
        notify_truncated_output(truncated)

'''
Dump the ospf route entries that are present in the ospf sync list
'''
class ospfSyncViewDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"family": "all"}
        if values and (len(values) == 1):
            params = {"family": values[0]}
        reply = remote_server.ospfSyncViewDump(**params)
        if (reply):
            if namespace.verbose:
                print(json.dumps(reply, sort_keys = True, indent = 2))
                return
            ospf_sync_view = []
            ospf_sync_view.append(["Address", "Netmask", "Nbr IP", "Intf",
                "Synced", "Sync_Action"])
            if "ospf_sync_view" in reply:
                for entry in reply["ospf_sync_view"]:
                    ospf_sync_view.append([entry["addr"], entry["netmask"],
                        entry["neighbor_ip"], entry["intf"], entry["synced"],
                        str(entry["sync_action"])])
            pretty_print_table(ospf_sync_view)

'''
Dump the bgp route entries that are present in the bgp sync list
'''
class bgpSyncViewDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            params = {"seg":values[0]}
        params.update({"debug":"bgp_sync_view_dump"})
        reply = remote_server.bgpSyncViewDump(**params)
        bgp_sync_view = []
        bgp_sync_view.append(["Address", "Netmask", "Nbr IP", "Intf", "Synced", "Sync_Action"])
        for entry in reply["bgp_sync_view"]:
            bgp_sync_view.append([entry["addr"], entry["netmask"], entry["neighbor_ip"],
                                  entry["intf"], entry["synced"], str(entry["sync_action"])])
        pretty_print_table(bgp_sync_view)


class bgpRedisDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 3):
                params = {"dip": values[0], "seg": values[1], "ip_fam": values[2]}
            elif (len(values) == 2):
                params = {"dip": values[0], "seg": values[1], "ip_fam": "all"}
            elif (len(values) == 1):
                params = {"dip": values[0], "seg": "all", "ip_fam": "all"}
        else:
            params = {"dip":"all", "seg": "all", "ip_fam": "all"}

        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})
        reply = remote_server.bgpRedisDump(**params)
        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        bgp_redis_dump = []
        bgp_redis_dump.append(["Address", "Netmask", "Gateway", "Nbr IP", "Nbr ID", "Metric", "Redis Metric", "Type", "Intf", "SEG", "Communities", "Flags"])
        for entry in reply["bgp_redis_dump"]:
            bgp_redis_dump.append([entry["addr"], entry["netmask"], entry["gateway"], entry["neighbor_ip"], entry["neighbor_id"], str(entry["metric"]), str(entry["redis_metric"]), str(entry["metric_type"]), entry["intf"], entry["segId"], str(entry["communities"]), str(hex(entry["flags"]))])
        pretty_print_table(bgp_redis_dump)
        print("O - Intra Area, IA - Inter Area, OE1 - External 1, OE2 - External 2")
        notify_truncated_output(truncated)

class bgpAggDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 3):
                params = {"dip": values[0], "seg": values[1], "ip_fam": values[2]}
            elif (len(values) == 2):
                params = {"dip": values[0], "seg": values[1], "ip_fam": "all"}
            elif (len(values) == 1):
                params = {"dip": values[0], "seg": "all", "ip_fam": "all"}
        else:
            params = {"dip":"all", "seg": "all", "ip_fam": "all"}

        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})
        reply = remote_server.bgpAggDump(**params)
        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        bgp_agg_dump = []
        bgp_agg_dump.append(["Segment", "Address", "Masklen", "AS-set",
                             "Summary-only", "Marker", "RefCnt"])
        for entry in reply["bgp_agg_dump"]:
            bgp_agg_dump.append([str(entry["seg"]), entry["addr"], str(entry["masklen"]),
                                 entry["asSet"], entry["summaryOnly"], str(entry["marker"]),
                                 str(entry["refCnt"])])
        pretty_print_table(bgp_agg_dump)
        print("Marker decode: 0 - NOT_MARKED, 1 - MARKED_PRESENT, 2 - MARKED_UPDATE")
        notify_truncated_output(truncated)


class ospfRedisDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 3):
                params = {"dip": values[0], "ip_fam":values[1], "seg": values[2]}
            elif (len(values) == 2):
                 params = {"dip": values[0], "ip_fam": values[1], "seg": "all"}
            elif (len(values) == 1):
                params = {"dip":values[0], "seg": "all", "ip_fam": "all"}
        else:
            params = {"dip": "all", "seg": "all", "ip_fam": "all"}

        params.update({"debug":"ospf_redis_dump",
                  "timeout_ms": get_timeout_ms(namespace) // 10,
                  "limit": get_entry_limit(namespace)})
        reply = remote_server.ospfRedisDump(**params)
        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        ospf_redis_dump = []
        ospf_redis_dump.append(["Address", "Netmask", "Gateway", "Nbr IP",
                                "Nbr ID", "Metric", "Redis Metric", "OSPF Cost",
                                "Type", "Intf", "Flags", "Seg"])
        for entry in reply["ospf_redis_dump"]:
            ospf_redis_dump.append([entry["addr"], entry["netmask"], entry["gateway"],
                entry["neighbor_ip"], entry["neighbor_id"], str(entry["metric"]),
                str(entry["redis_metric"]), str(entry["cost"]), entry["metric_type"],
                entry["intf"], str(hex(entry["flags"])), entry["segId"]])
        pretty_print_table(ospf_redis_dump)
        print("O - Intra Area, IA - Inter Area, OE1 - External 1, OE2 - External 2")
        notify_truncated_output(truncated)

class ospfAggDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (values and len(values) == 3):
            params = {"dip": values[0], "seg_id": values[1], "ip_fam": values[2]}
        elif (values and len(values) == 2):
            params = {"dip": values[0], "seg_id": values[1], "ip_fam": "all"}
        elif (values and len(values) == 1):
            params = {"dip": values[0], "seg_id": "all", "ip_fam": "all"}
        else:
            params = {"dip": "all", "seg_id": "all", "ip_fam": "all"}

        params.update({"debug":"ospf_agg_dump",
                  "timeout_ms": get_timeout_ms(namespace) // 10,
                  "limit": get_entry_limit(namespace)})
        reply = remote_server.ospfAggDump(**params)
        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        ospf_agg_dump = []
        ospf_agg_dump.append(["Address", "Masklen", "Tag", "Metric",
                                "MetricType", "NoAdv", "RefCnt", "Marker"])
        for entry in reply["ospf_agg_dump"]:
            ospf_agg_dump.append([entry["addr"], str(entry["netmask"]),
                                 str(entry["tag"]), str(entry["metric"]), entry["metricType"],
                                 entry["noAdv"], str(entry["refCnt"]), str(entry["marker"])])
        pretty_print_table(ospf_agg_dump)
        print("Marker decode: 0 - NOT_MARKED, 1 - MARKED_PRESENT, 2 - MARKED_UPDATE")
        notify_truncated_output(truncated)


class verboseRouteDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        pretty_file_name = None
        if len(values) == 1:
            params = {"arg1": values[0], "arg2": "all", "arg3": "all"}
        elif len(values) == 2:
            params = {"arg1": values[0], "arg2": values[1], "arg3": "all"}
        elif len(values) == 3:
            params = {"arg1": values[0], "arg2": values[1], "arg3": values[2]}
        elif len(values) == 4:
            params = {"arg1": values[0], "arg2": values[1], "arg3": values[2]}
            pretty_file_name = values[3]
        else:
            params = {"arg1": "all", "arg2": "all", "arg3": "all"}
        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})
        reply = remote_server.unifiedRouteDebugDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if pretty_file_name is None:
            print(json.dumps(reply, sort_keys = True, indent = 2))
        else:
            with open(pretty_file_name, 'w') as file:
                pretty_print_routes(reply, file)
        notify_truncated_output(truncated)

class dceEdgesDebugDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dce_edge", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        reply = remote_server.dceEdgesDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        dce_edge = []
        dce_edge.append(["DCE LogicalId", "V4 Address", "V6 Address", "Peer Tun Pref",
            "Private", "Type", "VCMP Port", "IKE Port", "NAT-t Port", "MPLS Network"])
        for entry in reply["dce_edge"]:
            dce_edge.append([entry["dceId"], entry["dce_addr"], entry["dce_addr6"],
                entry["peer_tun_pref"], entry["private"], entry["type"], str(entry["VCMPPort"]),
                str(entry["IKEPort"]), str(entry["NATTPort"]), str(entry['private_network_id'])])
        pretty_print_table(dce_edge)

class hubListDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            params = {"debug":"hub_list", "segment": values}
        else:
            params = {"debug":"hub_list", "segment": "all"}
        reply = remote_server.hubListDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        dce_edge = []
        dce_edge.append(["LogicalId", "Type", "HUB_ORDER", "VPN_HUB_ORDER", "Is_cluster"])
        for entry in reply["hub_list"]:
            dce_edge.append([entry["vceid"], entry["type"], str(entry["hub_order"]),
str(entry["vpn_hub_order"]), str(entry["is_hub_cluster"])])
        pretty_print_table(dce_edge)

class localSubnetDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"subnets"}
        reply = remote_server.localSubnetDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        subnets = []
        subnets.append(["Address", "Netmask", "Interface", "Secure"])
        for entry in reply["subnets"]:
            subnets.append([entry["addr"], entry["netmask"], entry["interface"],
                           str(entry["secure"])])
        pretty_print_table(subnets)

class staticRouteDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"routes", "ip_fam": "all"}
        if values:
            if (len(values) == 1):
                params.update({"ip_fam": values[0]})
            else:
                print("Invalid no.of Arguments")
                return
        reply = remote_server.staticRouteDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        routes = []
        routes.append(["Address", "Netmask", "Next Hop", "Destination", "Type", "Interface", "Metric","VLAN", "SegId"])
        for entry in reply["routes"]:
            vlan_id = str(entry["vlan_id"])
            if vlan_id == "524287":
                vlan_id = "N/A"
            routes.append([entry["addr"], entry["netmask"], entry["next_hop"], entry["dst_id"], entry["type"], entry["interface"], str(entry["metric"]), vlan_id, str(entry["segment_id"])])
        pretty_print_table(routes)

class PRDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"prdump", "logical_id": values[0]}
        reply = remote_server.PRDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class metricTableDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"logical_id": values[0], "segment_id": "all"}
        elif len(values) == 2:
            params = {"logical_id": values[0], "segment_id": values[1]}
        else:
            params = {"logical_id": "all", "segment_id": "all"}
        reply = remote_server.edgeMetricTableDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class PRStatsDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) == 1):
                params = {"debug":"prstatsdump","peer_id":values[0],"detailed":"all"}
                if values[0] == "detailed":
                    params = {"debug":"prstatsdump","peer_id":"all","detailed":values[0]}

            if (len(values) == 2):
                params = {"debug":"prstatsdump","peer_id":values[0],"detailed":values[1]}

        else:
            params = {"debug":"prstatsdump","peer_id":"all","detailed":"all"}

        reply = remote_server.PRDebugStatsDump(**params)

        pi_stats = reply['peer_stats_dump']
        print(json.dumps(reply, sort_keys = True, indent = 2))

class loggerSetSquelchState(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        log_squelch_state = -1
        log_squelch_max = -1
        for i in range (len(values)):
            if  values[i].startswith("max="):
                log_squelch_max = int(values[i].split("=")[1])
            elif values[i] == "on":
                log_squelch_state = 1
            elif values[i] == "off":
                log_squelch_state = 0
        if (log_squelch_state == -1):
            print("invalid log squelching stat: ", log_level)
            return 0
        params = {"state":log_squelch_state, "max":log_squelch_max}
        reply = remote_server.loggerSetSquelchState(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class loggerCtxOnOff(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        log_name = ""
        log_enable = ""
        for i in range (len(values)):
            if  values[i].startswith("name="):
                log_name = values[i].split("=")[1]
            elif values[i].startswith("enable="):
                log_enable = values[i].split("=")[1]
        if not log_name or not log_enable:
            print("Error: Expected 2 arguments")
            return -1
        params = {"name":log_name, "enable":log_enable}
        reply = remote_server.loggerCtxOnOff(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))
        return 0


class loggerOverrideDefaultsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        log_level = -1
        log_modules = ""
        logX = 0
        for i in range (len(values)):
            if values[i] == "logX":
                logX = 1
            elif  values[i].startswith("module="):
                log_modules = values[i].split("=")[1].split(",")
                log_modules = [x.strip() for x in log_modules]
                log_modules = ",".join(log_modules)
            elif values[i].isdigit():
                log_level = int(values[i])
        # if  log_level >= 0 and < max its invalid.
        if not (log_level >= 0  and  log_level <= 8):
            print("invalid log level : ", log_level)
            return 0
        # modules should be with in our defined modules range.
        params = {"level":log_level, "module":log_modules, "logX":logX}
        reply = remote_server.loggerOverrideDefaults(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ikeLoggerOverrideDefaultsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) <  3:
            print("Insufficient Arguments")
            return
        if (values[0].isdigit() and values[1].isdigit() and
                (values[2].isdigit() and int(values[2]) in [0,1])):
            params = {"global_level":int(values[0]), "ike_level":int(values[1]),
                      "enable_notice":int(values[2]),"module_level":"None"}
        else:
            print("Invalid Arguments")
            return
        if len(values) > 3:
            params["module_level"] = values[3]
        reply = remote_server.ikeLoggerOverrideDefaults(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

'''
Print the stats in a pretty tabular way
'''
def get_max_width(table, index):
    return max([len(row[index]) for row in table])

def pretty_print_table(table, file=sys.stdout, align_left=False):
    col_paddings = []

    for i in range(len(table[0])):
        col_paddings.append(get_max_width(table, i))

    for row in table:
        file.write((row[0].encode('UTF-8').ljust(col_paddings[0] + 1).decode()))
        for i in range(1, len(row)):
            if align_left:
                col = row[i].encode('UTF-8').ljust(col_paddings[i] + 2)
            else:
                col = row[i].encode('UTF-8').rjust(col_paddings[i] + 2)
            file.write(col.decode())
        file.write("\n")

def format_app_string(app_id, app_string):
    output = app_string + "(" + str(app_id) + ")"
    return output

def pretty_print_current_apps(reply, file=sys.stdout):
    app_stats = []
    app_stats.append(["SRC IP", "DST IP", "DST PORT", "PROTOCOL", "SEGID", "APPLICATION", "HOSTNAME", "APP CLASS", "PATH"])
    for conversation in reply:
        endpoints = conversation["endpoints"]
        app_stats.append([endpoints["innerIp"], endpoints["outerIp"], str(endpoints["outerPort"]), str(conversation["network"]), str(endpoints["segmentId"]),
                          format_app_string(conversation["application"], conversation["applicationString"]),
                          endpoints["outerHostName"], format_app_string(conversation["appClass"], conversation["appClassString"]), conversation["flowPath"]])
    pretty_print_table(app_stats, file)

class currentAppsDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {
            "debug":"current_apps",
            "timeout_ms": get_timeout_ms(namespace) // 10,
            "limit": get_entry_limit(namespace),
            "sip": "all",
            "dip": "all",
            "dport": "all",
            "app_id":"all"
            }
        reply = remote_server.chatStatsDebugDump(**params)
        truncated = reply["truncated"]
        reply = reply["stats"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        pretty_print_current_apps(reply)
        notify_truncated_output(truncated)

def _dump_hash_map_bkt_data(data, headerFn, entryFn, namespace):
    if namespace.verbose:
        for entry in data:
            print(namespace.verbose_prefix + json.dumps(entry, sort_keys = True, indent = 2))
            namespace.verbose_prefix = ", "
    else:
        output = []
        output.append(headerFn())
        for entry in data:
            output.append(entryFn(entry))
        pretty_print_table(output)

def dump_hash_map_bkt_iter(commandFn, params, dataName, headerFn, entryFn, namespace):
    '''
    Common API to iteratively dump hash maps. The debug API must use the bkt iter approach and
    support the following data elements:
    - Input:
        - bkt_pos: Current bucket position. Will be initially set to 0 to indicate pagination is
            requested.
    - Output:
        - bkt_pos: The next bucket to be processed. Will be used as input in the next iteration
        - count: The number of data elements returned in reply[dataName]
        - truncated: 1 if max time or max elements is reached; 0 otherwise
        - dataName: array of entries dumped

    Params:
        - commandFn: jsonRPC Debug API to be called
        - params: params to pass to jsonRPC
        - dataName: json key where dumped entries are stored as an array
        - headerFn: Function that returns header names as an array; Header will be printed each
            iteration of the dump
        - entryFn: Function that returns entry values as an array
    '''
    namespace.verbose_prefix = ""
    if namespace.verbose:
        print("[")
    params['bkt_pos'] = 0
    truncated = 0
    count = params['count']
    while params['bkt_pos'] >= 0 and truncated == 0:
        reply = commandFn(**params)
        if "error" in reply:
            print(namespace.verbose_prefix + json.dumps(reply, sort_keys = True, indent = 2))
            break
        _dump_hash_map_bkt_data(reply[dataName], headerFn, entryFn, namespace)
        truncated = reply["truncated"]
        params['bkt_pos'] = reply['bkt_pos']
        if count > 0:
            params['count'] = params['count'] - reply['count']
            if params['count'] <= 0:
                break
    if namespace.verbose:
        print("]")
    else:
        notify_truncated_output(truncated)

def get_nat_entries_header():
    return ["TYPE", "OSIP", "ODIP", "OSPORT", "ODPORT", "OPROTO", "OFLOW",
            "MSIP", "MDIP", "MSPORT", "MDPORT", "MPROTO", "MFLOW", "SEGID", "REFCNT"]
def get_nat_entries_data(entry):
    orig = entry["original"]
    mod = entry["modified"]
    return [entry["type"], orig["sip"], orig["dip"], str(orig["sport"]),
            str(orig["dport"]), str(mod["protocol"]), str(entry["orig_flow_label"]),
            mod["sip"], mod["dip"], str(mod["sport"]), str(mod["dport"]),
            str(mod["protocol"]), str(entry["mod_flow_label"]),
            str(entry["segment_id"]), str(entry["ref_count"])]

class natDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"nat_dump", "dip": "all", "dir": "orig", "ipversion": 0,
            "timeout_ms": get_timeout_ms(namespace) // 10, "count":get_entry_limit(namespace)}
        if len(values) > 2:
            filters=["type","proto","sip","dip","sport","dport",
                     "msip","mdip","msport","mdport","count"]
            process_filter_params(params, filters, values[2:])
        if len(values) > 1:
            if values[1] == "v4":
                params.update({"ipversion":4})
            elif values[1] == "v6":
                params.update({"ipversion":6})
            elif values[1] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        if len(values) > 0:
            params.update({"dir": values[0]})
        dump_hash_map_bkt_iter(remote_server.natDump, params, "nat_dump",
            get_nat_entries_header, get_nat_entries_data, namespace)

class staleNatDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "stale_nat_dump"}
        params.update({"timeout_ms": get_timeout_ms(namespace) // 10})
        params.update({"count": get_entry_limit(namespace)})
        reply = remote_server.staleNatDump(**params)

        stale_nat_entries = reply['stale_nat']
        truncated = reply['truncated']
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        output = []
        output.append(["TYPE", "OSIP", "ODIP", "OSPORT", "ODPORT", "OPROTO",
                       "MSIP", "MDIP", "MSPORT", "MDPORT", "MPROTO", "SEGID",
                       "REFCNT"])
        for nat_entry in stale_nat_entries:
            orig = nat_entry["original"]
            mod = nat_entry["modified"]
            output.append([ nat_entry["type"], orig["sip"], orig["dip"], str(orig["sport"]),
                           str(orig["dport"]), str(mod["protocol"]), mod["sip"], mod["dip"],
                           str(mod["sport"]), str(mod["dport"]), str(mod["protocol"]),
                           str(nat_entry["segment_id"]), str(nat_entry["ref_count"])])
        pretty_print_table(output)
        notify_truncated_output(truncated)

def get_nat_port_entries_header():
    return ["SIP", "DIP", "DPORT", "PROTO", "FREE", "OFFSET", "TAILQ", "TOTAL",
            "MISS", "REFCNT"]
def get_nat_port_entries_data(entry):
    return [str(entry["src_ip"]), str(entry["dst_ip"]), str(entry["dst_port"]),
           str(entry["protocol"]), str(entry["port_freecount"]),
           str(entry["port_offset"]), str(entry["ports_in_tailq"]),
           str(entry["tot_ports"]),  str(entry["port_allot_miss"]),
           str(entry["ref_cnt"])]

class natPortDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"nat_port_dump", "count":0, "ipversion": 0}
        params.update({"timeout_ms": get_timeout_ms(namespace) // 10})
        params.update({"count": get_entry_limit(namespace)})
        if len(values) > 1:
            filters=["proto","sip","dip","dport","count"]
            process_filter_params(params, filters, values[1:])
        if len(values) > 0:
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        dump_hash_map_bkt_iter(remote_server.natPortDump, params, "nat_port_dump",
            get_nat_port_entries_header, get_nat_port_entries_data, namespace)

def get_nat_port_restricted_entries_header():
    return ["IN SIP", "IN SPORT", "OUT SIP", "OUT SPORT", "PROTO",
           "IN USE", "REFCNT"]
def get_nat_port_restricted_entries_data(entry):
    return [str(entry["inside_src_ip"]), str(entry["inside_src_port"]),
           str(entry["outside_src_ip"]), str(entry["outside_src_port"]),
           str(entry["protocol"]), str(entry["in_use_cnt"]),
           str(entry["ref_cnt"])]

class natPortRestrictedDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"nat_port_restricted_dump", "count":0, "ipversion": 0}
        params.update({"timeout_ms": get_timeout_ms(namespace) // 10})
        params.update({"count": get_entry_limit(namespace)})
        if len(values) > 1:
            filters=["proto","inside_sip","outside_sip","inside_sport","outside_sport","count"]
            process_filter_params(params, filters, values[1:])
        if len(values) > 0:
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        dump_hash_map_bkt_iter(remote_server.natPortRestrictedDump,
            params, "nat_port_restricted_dump",
            get_nat_port_restricted_entries_header, get_nat_port_restricted_entries_data,
            namespace)

def sortNatSummaryOutput(e):
    return int(e[3])

class natSummaryAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"nat_dump", "ipversion": 0,
            "timeout_ms": get_timeout_ms(namespace) // 10, "count":get_entry_limit(namespace)}
        if len(values) > 2:
            filters=["type","proto","peer_id","seg",
                    "sip","dip","sport","dport","msip","mdip","count"]
            process_filter_params(params, filters, values[2:])
        if len(values) > 1:
            if values[1] == "v4":
                params.update({"ipversion":4})
            elif values[1] == "v6":
                params.update({"ipversion":6})
            elif values[1] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        if len(values) > 0:
            params.update({"dir": values[0]})
        reply = remote_server.natSummary(**params)
        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        truncated = reply["truncated"]
        reply = reply["nat_summary"]
        output = []
        for entry in reply:
            seg = "*" if entry["segment_id"] < 0 else str(entry["segment_id"])
            output.append([entry["peer_id"], seg, entry["ip"], str(entry["count"])])
        if len(reply) < 1000:
            output.sort(reverse=True, key=sortNatSummaryOutput)
            output.insert(0, ["PEER_ID", "SEG", "IP", "COUNT*"])
        else:
            output.insert(0, ["PEER_ID", "SEG", "IP", "COUNT"])
        pretty_print_table(output)
        notify_truncated_output(truncated)

class pptpConnMapDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        reply = remote_server.pptpConnMapDump(debug="")
        print(json.dumps(reply, sort_keys=True, indent=2))

class pathUptimeDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"debug_path_uptime"}
        reply = remote_server.pathUptimeDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ipIdDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ipid_dump", "ipversion": 0,
            "timeout_ms": get_timeout_ms(namespace) / 10, "count":get_entry_limit(namespace)}
        if len(values) > 0:
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return

        reply = remote_server.ipIdDump(**params)
        truncated = reply["truncated"]
        reply = reply["ipid_dump"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        output = []
        output.append(["SRC", "DST", "PROT", "OFFSET", "USED", "FREE", "TOT", "REFCNT"]);
        for entry in reply:
            output.append([ entry["src"], entry["dst"], str(entry["proto"]),
                           str(entry["idoff"]),
                           str(entry["used_cnt"]),
                           str(entry["free_cnt"]),
                           str(entry["tot_cnt"]),
                           str(entry["ref_cnt"])])
        pretty_print_table(output)
        notify_truncated_output(truncated)

class haFlowDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        retry_only = False
        if values and ("retry" in values):
            values = re.sub(r'\s*retry\s*', '', values)
            retry_only = True
        if values:
            params = {"debug":"ha_flow_dump", "dip": values}
        else:
            params = {"debug":"ha_flow_dump", "dip": "all"}
        if retry_only:
            reply = remote_server.haFlowDumpRetry(**params)
        else:
            reply = remote_server.haFlowDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["INTF", "OSIP", "ODIP", "OSPORT", "ODPORT", "OPROTO", "DSCP",
                       "MSIP", "MDIP", "MSPORT", "MDPORT", "MPROTO",
                       "ROUTE", "MAC", "APP", "CLASS", "RETRY", "NRETRIES"])
        for entry in reply:
            output.append([entry["wan_intf"], entry["sip"], entry["dip"],
                           str(entry["sport"]), str(entry["dport"]), entry["proto"],
                           str(entry["dscp"]), entry["nat_sip"], entry["nat_dip"],
                           str(entry["nat_sport"]), str(entry["nat_dport"]),
                           entry["nat_proto"], entry["route_policy"],
                           entry["mac_addr"], entry["app_proto"],
                           entry["app_class"], str(entry["retry"]),
                           str(entry["retry_count"])])
        pretty_print_table(output)

class haDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ha_dump", "module": values[0]}
        reply = remote_server.haDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class haSwitchAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ha_switch"}
        reply = remote_server.haSwitch(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vrrpDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"vrrp_dump"}
        reply = remote_server.vrrpDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vrrpLoadAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"vrrp_load"}
        reply = remote_server.vrrpLoad(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vrrpShutdownAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"vrrp_shutdown"}
        reply = remote_server.vrrpShutdown(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vrrpStartupAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"vrrp_start"}
        reply = remote_server.vrrpStartup(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vrrpEnableAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"vrrp_enable"}
        reply = remote_server.vrrpEnable(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vrrpSetPriorityAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"vrrp_set_priority","priority":values[0]}
        reply = remote_server.vrrpSetPriority(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vrrpResetPriorityAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"vrrp_reset_priority"}
        reply = remote_server.vrrpResetPriority(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class updateMgdRouteAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"update_mgd_route"}
        reply = remote_server.updateMgdRoutePolicy(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class applicationDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"applications"}
        reply = remote_server.applicationDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        applications = []
        applications.append(["NAME", "DISPLAY", "APP_ID", "CLASS_ID", "IP ROUTABLE", "PORT ROUTABLE"])
        for entry in reply["applications"]:
            ip_routable = False
            ip_port_map = entry["ip_port_map"]
            if ip_port_map["subnets"]:
                ip_routable = True

            port_routable = False
            proto_port_map = entry["proto_port_map"]
            if proto_port_map["tcp_ports"] or proto_port_map["udp_ports"]:
                port_routable = True

            applications.append([entry["name"], entry["display_name"], str(entry["id"]), str(entry["class"]), str(ip_routable), str(port_routable)])
        pretty_print_table(applications)

class appMapIP_PortDB(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"app_ip_port_db"}
        reply = remote_server.app_ip_port_db(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        entries = []
        entries.append(["IP ADDR", "NETMASK", "TCP_PORT(S)", "UDP_PORT(S)", "APPLICATION", "CLASS"])
        for entry in reply:
            entries.append([entry["ip_addr"], entry["netmask"], str(entry["tcp_ports"]), str(entry["udp_ports"]), entry["application"], entry["class"]])
        pretty_print_table(entries)

class ipPortCacheDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"app_ip_port_cache"}
        if values:
            if len(values) > 1:
                print("""Invalid no.of arguments provided.)
                      usage: --app_ip_port_cache [v4 | v6 | all]""")
                return
            if (len(values) == 1):
                 params.update({"ip_fam": values[0]})
        else:
            params.update({"ip_fam": "all"})

        reply = remote_server.app_ip_port_cache(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        entries = []
        entries.append(["IP ADDR", "PORT", "APPLICATION", "CLASS", "DPI/AppMap", "IDLE TIME MS",
                         "IS DEFAULT", "IS FQDN"])
        for entry in reply:
            entries.append([entry["ip_addr"], str(entry["port"]), entry["application"],
                           entry["class"], entry["dpi_source"], str(entry["idle_time_ms"]),
                           str(entry["not_found_match"]), str(entry["fqdn_match"])])
        pretty_print_table(entries)

class ipPortCacheFlush(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"app_ip_port_cache_flush"}
        reply = remote_server.app_ip_port_cache_flush(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))
        return

class appMapProtoPortDB(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"app_proto_port_db"}
        reply = remote_server.app_proto_port_db(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        applications = []
        pre_sort = []
        applications.append(["PORT", "PROTOCOL", "APPLICATION", "CLASS"])
        reply.sort(key=operator.itemgetter('port'))
        for entry in reply:
            protocol = "TCP"
            if entry["protocol"] == 17:
                protocol = "UDP"
            applications.append([str(entry["port"]), protocol, entry["application"], entry["class"]])
        pretty_print_table(applications)

class appMapFQDNDB(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"app_fqdn_db"}
        reply = remote_server.app_fqdn_db(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        applications = []
        applications.append(["FQDN", "APPLICATION", "CLASS"])
        for entry in reply:
            applications.append([entry["fqdn"], entry["application"], entry["class"]])
        pretty_print_table(applications)

class dnsNameCacheDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dns_name_cache", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        reply = remote_server.dnsNameCacheDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        num_entries = 0
        if reply:
            num_entries = len(reply)
        print("Total Cache Entries: %d" %(num_entries))

        dns_cache = []
        dns_cache.append(["NAME", "ADDRESS", "TTL(s)", "SOURCE", "APPMAP APPID"])
        for entry in reply:
            dns_cache.append([entry["name"], entry["address"], str(entry["ttl"]),
                             str(entry["source"]), str(entry["appid"])])
        pretty_print_table(dns_cache)

class dnsNameCacheLookupAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"dns_name_lookup":"", "ipversion":0}
        if (values):
            params.update({"dns_name_lookup":values[0]})
        else:
            print("Usage: debug.py --dns_name_lookup HOSTNAME [v4 | v6 | all]")
            return

        if (len(values) == 2):
            if values[1] == "v4":
                params.update({"ipversion":4})
            elif values[1] == "v6":
                params.update({"ipversion":6})
            elif values[1] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        elif (len(values) > 2):
            print("Usage: debug.py --dns_name_lookup HOSTNAME [v4 | v6 | all]")
            return
        reply = remote_server.dnsNameCacheLookup(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class dnsIpCacheDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dns_ip_cache", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        reply = remote_server.dnsIpCacheDebugDump(**params)
        dns_cache = []

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        num_entries = 0
        if reply:
            num_entries = len(reply)
        print("Total Cache Entries: %d" %(num_entries))
        dns_cache.append(["NAME", "ADDRESS", "TTL(s)", "SOURCE", "REFCNT", "APPID"])
        for entry in reply:
            dns_cache.append([entry["name"], entry["address"], str(entry["ttl"]),
                str(entry["source"]), str(entry["ref_cnt"]), str(entry["appid"])])
        pretty_print_table(dns_cache)

class dnsIpCacheLRUDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dns_ip_cache_lru", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        reply = remote_server.dnsIpCacheLRUDebugDump(**params)
        dns_cache = []

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        dns_cache.append(["NAME", "ADDRESS", "AGE(s)", "SOURCE", "REFCNT", "APPID"])
        for entry in reply:
            dns_cache.append([entry["name"], entry["address"], str(entry["last_used"]),
                str(entry["source"]), str(entry["ref_cnt"]), str(entry["appid"])])
        pretty_print_table(dns_cache)

class dnsIpCacheLookupAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"dns_ip_lookup":values[0]}
        reply = remote_server.dnsIpCacheLookup(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class dnsIpCacheFlushAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dns_ip_cache_flush", "ipaddr":"", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                params.update({"ipaddr":values[0]})
        reply = remote_server.dnsIpCacheFlush(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class dnsIpCacheUpdateTtlAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"ipaddr": values[0], "ttl": int(values[1])}
        reply = remote_server.dnsIpCacheUpdateTtl(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ikeResAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ike_stats"}
        reply = remote_server.ikeResDump(**params)
        tbl=[]
        max_val=[]
        curr_val=[]
        pipe_val=[]
        for key, val in reply["ike_sa_resource"].items():
            if "vc_tbl" in key:
                tbl.append([key, str(val)])
            elif "vc_qsec_max" in key:
                max_val.append([key, str(val)])
            elif "vc_qsec_curr" in key:
                curr_val.append([key, str(val)])
            elif "vc_qsec_pipe" in key:
                pipe_val.append([key, str(val)])
            else:
                print("Unknown key" + str(key))
        hdr = "="*50
        print("\nTable Counts")
        print(hdr)
        pretty_print_table(tbl)
        print("\nPIPE Values")
        print(hdr)
        pretty_print_table(pipe_val)
        print("\nMax Values")
        print(hdr)
        pretty_print_table(max_val)
        print("\nCurrent Values")
        print(hdr)
        pretty_print_table(curr_val)

class ikeDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ike", "ip_type": "all"}
        if values:
            if (len(values) == 1):
                params.update({"ip_type": values[0]})
            else:
                print("Invalid no.of Arguments")
                return
        reply = remote_server.ikeDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class pkiDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"pki"}
        reply = remote_server.pkiDebugDump(**params) or {}
        reply["pkiSettings"] = pki.get_pki_settings()
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ikeDownAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"cookie":values[0]}
        reply = remote_server.ikeDebugDown(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ikeDeleteP1SaAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"peerIp":values[0], "cookie":values[1]}
        reply = remote_server.ikeDebugDeleteP1Sa(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ikeDeleteTunnel(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"cookie":values[0]}
        reply = remote_server.ikeDeleteTunnel(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ikeChildsaDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ike_childsa", "ip_type": "all", "peer_ip": "all", "ikeSaSpi": "all", "count": "all"}
        if values:
            if (len(values) == 1):
                params.update({"ip_type": values[0]})
            elif (len(values) == 2):
                params.update({"ip_type": values[0], "peer_ip": values[1]})
            elif (len(values) == 3):
                params.update({"ip_type": values[0], "peer_ip": values[1], "ikeSaSpi": values[2]})
            elif (len(values) == 4):
                params.update({"ip_type": values[0], "peer_ip": values[1], "ikeSaSpi": values[2], "count": values[3]})
            else:
                print("Invalid no.of Arguments")
                return

        reply = remote_server.ikeChildsaDump(**params)

        if namespace.verbose or ("Error" in reply):
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        #first print the Security Policy
        ike_childsa = []
        ike_childsa.append(["Index", "Ref", "Cookie", "SpdId", "TunnelId", "Flags", "Dir",
                            "Spi", "PeerPort", "Auth", "Encr", "PFS", "Tunnel // Traffic",
                            "Pkts", "Drops", "Interface", "Secs"])
        for entry in reply["descriptors"]:
            ike_childsa.append([entry["index"], entry["Ref"], entry["cookie"], entry["SpdId"],
                                entry["tunnelId"],
                                entry["saFlags"], entry["dir"],
                                entry["SaSpi"],
                                entry["SaUdpEncPort"],
                                entry["auth_algs"], entry["encr_algs"],
                                entry["PFS"],
                                entry["tunnel_traffic"], entry["usage_pkts"],
                                entry["pktDrops"], entry["infs"], entry["usage"]])

        print("Child SA = %d" %(len(ike_childsa) -1))
        print("================================================================================"
              "================================================================================"
              "==============================")
        pretty_print_table(ike_childsa)

class ikeStalesaDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ike_staledsa", "ip_type": "all"}
        if values:
            if (len(values) == 1):
                params.update({"ip_type":values[0]})
            else:
                print("Invalid no of Arguments")
                return
        reply = remote_server.ikeStalesaDump(**params)

        if namespace.verbose or ("Error" in reply):
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        #first print the Security Policy
        ike_stalesa = []
        ike_stalesa.append(["Index", "Ref", "Cookie", "SpdId", "TunnelId", "Flags", "Dir",
                            "Spi", "PeerPort",
                            "Auth", "Encr", "Tunnel // Traffic", "Pkts","Drops", "Interface", "Secs"])
        for entry in reply["descriptors"]:
            ike_stalesa.append([entry["index"], entry["Ref"], entry["cookie"], entry["SpdId"],
                                entry["tunnelId"],
                                entry["saFlags"], entry["dir"],
                                entry["SaSpi"],
                                entry["SaUdpEncPort"],
                                entry["auth_algs"], entry["encr_algs"],
                                entry["tunnel_traffic"], entry["usage_pkts"],
                                entry["pktDrops"], entry["infs"], entry["usage"]])

        print("Total SA = %d" %(reply["sa_total"]))
        print("Stale SA = %d" %(len(ike_stalesa) -1))
        print("Unused SA = %d" %(reply["unused_sa"]))
        print("================================================================================"
              "================================================================================"
              "==============================")
        pretty_print_table(ike_stalesa)

class ikeSaDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ike_sa", "ip_type": "all", "peer_ip": "all",
                                         "count": "all", "type": "local"}
        if values:
            if (len(values) == 1):
                params.update({"ip_type": values[0]})
            elif (len(values) == 2):
                params.update({"ip_type": values[0], "peer_ip": values[1]})
            elif (len(values) == 3):
                params.update({"ip_type": values[0], "peer_ip": values[1], "count": values[2]})
            else:
                print("Invalid no.of Arguments")
                return

        reply = remote_server.ikeSaDump(**params)

        if namespace.verbose or ("Error" in reply):
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        #first print the Security Policy
        ike_sa = []
        ike_sa.append(["Index", "TunnelId", "Cookie", "IKEversion", "Flags", "Dir", "Auth",
            "DH_Group", "Encrypt", "MAC",
                       "SPI-I", "SPI-R", "LocalIP",  "PeerAddr", "Secs", "ChildSAS"])
        for entry in reply["sa_entries"]["descriptors"]:
            ike_sa.append([str(entry["index"]), str(entry["tunnelId"]), str(entry["cookie"]),
                           entry["ike"], entry["flags"], str(entry["dir"]),
                           str(entry["localAuth"]), str(entry["dhGroup"]),
                           entry["encryptAlgorithm"],
                           entry["macAlgorithm"],
                           entry["ikeSpiI"], entry["ikeSpiR"],
                           entry["localIp"],entry["peer"],
                           entry["secs"],str(entry["childSa"])])

        print("IKE SA     Total Count = %d" % reply["sa_entries"]["tot_count"])
        hdr = "="*200
        print(hdr)
        pretty_print_table(ike_sa)

class ikeSpdDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ike_spd", "peer_ip" : "all"}

        if values:
            if (len(values) == 1):
                params.update({"peer_ip": values[0]})
            else:
                print("Invalid number of arguments")
                return

        reply = remote_server.ikeSpdDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        ike_spd = []
        ike_spd.append(["Version","Cookie","Mode","SecuProto","P1Auth","P1Encr",
                        "DHGroup","DPDTimeout","P1SALife","P2Auth", "P2Encr","PFS",
                        "P2SALife", "TunnelEndpoints"])
        for entry in reply["spds"]:
            ike_spd.append([entry["ike_version"], entry["cookie"], entry["mode"],
                           entry["p2_secu_proto"], entry["p1_auth_algo"], entry["p1_encr_algo"],
                            str(entry["p1_dh_group"]), str(entry["dpd_timeout_secs"]),
                            str(entry["p1_sa_life_secs"]), entry["p2_auth_algo"],
                            entry["p2_encr_algo"], entry["p2_pfs"],
                            str(entry["p2_sa_life_secs"]), entry["tunnel"]])

        print("Security Policy")
        print("================================================================================"
              "===============================================================================")
        pretty_print_table(ike_spd)

class endpointDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"endpoints", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return

        reply = remote_server.endpointDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        endpoints = []
        endpoints.append(["src_ip", "dst_ip"])
        for entry in reply:
            endpoints.append([str(entry["src_ip"]), str(entry["dst_ip"])])
        pretty_print_table(endpoints)

class wirelessSignalStrengthAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            filename = '/tmp/USB/' + values[0] + '_periodic.txt'
            fp = open(filename, 'r')
            contents = fp.read()
            json_value = json.loads(contents)
            sigStrength = int(json_value['SigPercentage'])//20
            fp.close()
            #print("Wireless link signal strength = " + str(sigStrength))
            params = {"interface":values[0], "sigStrength":sigStrength}
            reply = remote_server.wirelessSignalStrengthUpdate(**params)
            print(json.dumps(reply, sort_keys = True, indent = 2))
        except ValueError:
            print("ValueError: No JSON object could be decoded")
            return 0
        except IOError:
            print("IOError: File %s not found" % filename)
            return 0

class handoffqDbgDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1 and values[0] == "reset":
            params = {"debug":"handoffqdbg_reset"}
            reply = remote_server.handoffqDbgReset(**params)
        else:
            params = {"debug":"handoffqdbg"}
            reply = remote_server.handoffqDbgDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        if len(values) != 0:
            return

        fields = ["name", "tid", "qlimit", "enq", "deq", "drops", "qlength",
                  "wmark", "wmark_1min", "wmark_5min"]
        handoffqdbg = []
        handoffqdbg.append(fields)
        for entry in reply["handoffq"]:
            handoffqdbg.append([str(entry[f]) for f in fields ])
        pretty_print_table(handoffqdbg)

class admissionControlAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        reply = {}
        if len(values):
            if values[0] == "enable":
                if len(values) == 3 and values[1] == "threshold" and values[2].isdigit():
                    params = {"state" : 1, "threshold" :int(values[2]) }
                else:
                    params = {"state" : 1, "threshold" : 30 }
                reply = remote_server.admissionControlConfig(**params)
            elif values[0] == "disable":
                params = {"state" : 0, "threshold" : 30 }
                reply = remote_server.admissionControlConfig(**params)
        else:
            params = {"debug":"admissionControlStatus"}
            reply = remote_server.admissionControlStatus(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))


class linkBwCapDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"bwcap"}
        reply = remote_server.linkBwCapDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        linkbw = []
        linkbw.append(["VCEID", "CurCap", "OrigCap", "wstart",
                       "decr", "incr", "test", "force",
                       "Nforced", "pkts", "nacks",
                       "rxkbps", "txkbps", "abort", "init", "netcap",
                       "delta", "minlat", "avglat"])
        for entry in reply["bwcap"]:
            linkbw.append([entry["vceid"], str(entry["bwcap"]),
                           str(entry["msrcap"]),
                           str(entry["wstart"]),
                           str(entry["decr"]), str(entry["incr"]),
                           str(entry["test"]), str(entry["force"]),
                           str(entry["Nforced"]), str(entry["pkts"]),
                           str(entry["nacks"]), str(entry["rxbps"]),
                           str(entry["txbps"]),
                           str(entry["abort"]), str(entry["init"]),
                           str(entry["netcap"]), str(entry["delta"]),
                           str(entry["minlat"]), str(entry["avglat"])])
        pretty_print_table(linkbw)

class vpnTestDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (values):
            segid = int(values[0])
        else:
            segid = 0
        params = {"segid": segid}
        reply = remote_server.vpnTestDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class remoteServicesDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"remote":"services"}
        reply = remote_server.remoteServicesDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class NetQoSDebug(argparse.Action):

    def appendStats(self, qos_stats, stats):
        qos_stats.append([str(stats["Peer"]),
            str(stats["bw_cap"]),
            str(format(stats["weight"], '.2f')),
            str(stats["bytes_rate"]),
            str(stats["pkts_rate"]),
            str(stats["pkts_queued"]),
            str(stats["bytes_queued"]),
            str(stats["pkts_dropped"]),
            str(stats["bytes_dropped"])])

    def __call__(self, parser, namespace, values, option_string=None):
        if ((values[2] != "stats" and values[2] != "clear_drops") or
                ((values[1] != "all") and
                 ((not values[1].isdigit()) or (int(values[1]) < 0)))):
            print(""" Invalid arguments.
               usage: --qos_net [<peer_id> | gateway ]', '[ all | <segid> ]',
               '[ stats | clear_drops ]]""")
            return
        params = {"peer_id":values[0], "segment": values[1], "action": values[2]}
        reply = remote_server.NetQoSDebug(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        if len(reply) < 1:
            print(json.dumps("Peer with logical-id " + values[0]+" not found",
                sort_keys = True, indent = 2))
            return
        if values[2] == "stats":
            net_qos_stats = []
            net_qos_stats.append(["Endpoint/Class", "BW Cap (Kbps)", "Weight",
                "Kbps (10s win)", "PPS (10s win)", "Queued pkts",
                "Queued bytes", "Dropped pkts", "Dropped bytes"])
            for entry1 in reply:
                peer = entry1["peer"]
                stats = peer["stats"]
                self.appendStats(net_qos_stats, stats)

                control_stats = peer.get("control_stats")
                if control_stats:
                    control_stats["Peer"] = "  " + control_stats["Peer"]
                    self.appendStats(net_qos_stats, control_stats)
                segments = peer.get("segments")
                if segments:
                    for segment in segments:
                        stats = segment["stats"]
                        stats["Peer"] = "  " + stats["Peer"]
                        self.appendStats(net_qos_stats, stats)
                        cos_stats = segment["cos"]
                        for cos in cos_stats:
                            stats = cos["stats"]
                            stats["Peer"] = "    " + stats["Peer"]
                            self.appendStats(net_qos_stats, stats)
            pretty_print_table(net_qos_stats)
        elif values[2] == "clear_drops":
            print(json.dumps(reply, sort_keys= True, indent=2))
        return 0

class LinkQoSDebug(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"peer_id":values[0], "action": values[1]}
        reply = remote_server.LinkQoSDebug(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        if values[1] == "stats":
            link_qos_stats = []
            link_qos_stats.append(["Interface", "Link-Id/Peer-Id", "BW-Cap Kbps",
                "10-sec-win kbps", "Last slot Kbps", "PPS (10s win)", "Queued pkts", "Queued bytes",
                "Dropped pkts", "Dropped bytes"])
            for stats in reply:
                link_qos_stats.append([stats["ifname"], stats["logical_id"],
                    str(stats["bw_cap"]),
                    str(stats["bytes_rate"]),
                    str(stats["curr_bytes_rate"]),
                    str(stats["pkts_rate"]),
                    str(stats["pkts_queued"]),
                    str(stats["bytes_queued"]),
                    str(stats["pkts_dropped"]),
                    str(stats["bytes_dropped"])])

            pretty_print_table(link_qos_stats)
        elif values[1] == "clear_drops":
            print(json.dumps(reply, sort_keys= True, indent=2))
        return 0

class LinkQoSDebugPQ(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"action": values[0]}
        reply = remote_server.LinkQoSDebugPQ(**params)
        print(json.dumps(reply, sort_keys= True, indent=2))
        return 0

class NetQoSDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "handle": 0, "max_time_us": 800, "steps": 64 }
        if LOGFILE != "NIL":
            params.update({"logfile": LOGFILE})
        loop = 0
        while params["handle"] != -1:
            loop += 1
            reply = remote_server.NetQoSDump(**params)
            if "error" in reply:
                print(json.dumps(reply, sort_keys = True, indent = 2))
                return
            if LOGFILE == "NIL":
                vc_qos_view_str(json.dumps(reply))
            else:
                print(json.dumps(reply, sort_keys = True, indent = 2))
            params["handle"] = reply["handle"]
        print("NetQoSDump: loop = %d" % loop)

class LinkQoSDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "handle": 0, "max_time_us": 800, "steps": 64 }
        if LOGFILE != "NIL":
            params.update({"logfile": LOGFILE})
        loop = 0
        while params["handle"] != -1:
            loop += 1
            reply = remote_server.LinkQoSDump(**params)
            if "error" in reply:
                print(json.dumps(reply, sort_keys = True, indent = 2))
                return
            if LOGFILE == "NIL":
                vc_qos_view_str(json.dumps(reply))
            else:
                print(json.dumps(reply, sort_keys = True, indent = 2))
            params["handle"] = reply["handle"]
        print("LinkQoSDump: loop = %d" % loop)

class flowStats(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            params = {"debug": "flow_stats", "logical_id": values}
        else:
            params = {"debug": "flow_stats"}
        reply = remote_server.flowStats(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        if len(reply) <= 1:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        flow_stats = []
        flow_stats.append(["Path", "Total Flows", "TCP Flows", "UDP Flows",
                           "ICMP Flows", "Other Flows"])
        for entry in reply:
            flow_stats.append([entry["Path"], str(entry["Total Flows"]),
                str(entry["Active TCP Flows"] - entry["Dead TCP Flows"]),
                str(entry["Active UDP Flows"] - entry["Dead UDP Flows"]),
                str(entry["Active ICMP Flows"] - entry["Dead ICMP Flows"]),
                str(entry["Active other Flows"] - entry["Dead other Flows"])])
        pretty_print_table(flow_stats)

class uptime(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"uptime"}
        reply = remote_server.uptime(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        elapsed_ms = reply["uptime"]
        m,s = divmod((elapsed_ms//1000),60)
        h,m = divmod(m,60)
        d,h = divmod(h,24)
        print("Uptime: %02d:%02d:%02d, %d days" % (h,m,s,d))
        print("Start: %s, Current: %s" % (str(reply["start"]), str(reply["current"])))

class ospfDumpAction(argparse.Action):
    def get_ospfd_vrf_name(self, seg_id):
        if seg_id == "0":
            return "default"
        else:
            return "vc-" + str(seg_id)

    def __call__(self, parser, namespace, values, option_string=None):
        family = "all"
        vrf = "all"
        if values:
            if len(values) == 2:
                family = values[0]
                vrf = "all" if values[1] == "all" else self.get_ospfd_vrf_name(values[1])
            elif len(values) == 1:
                family = values[0]

        if (family == "all") or (family == "v4"):
            ospfInterfacesDump = subprocess.check_output(
                    "vtysh " + "-d ospfd " + "-c \"show ip ospf vrf " + vrf + " interface\"",
                    universal_newlines=True, shell=True)
            if len(ospfInterfacesDump) > 0:
                    print("Interfaces Dump")
                    print("===============")
                    print(ospfInterfacesDump)

            ospfNeighborsDump = subprocess.check_output(
                    "vtysh " + "-d ospfd " + "-c \"show ip ospf vrf " + vrf + " neighbor\"",
                    universal_newlines=True, shell=True)
            if len(ospfNeighborsDump) > 0:
                    print("Neighbors Dump")
                    print("==============")
                    print(ospfNeighborsDump)

            ospfRoutesDump = subprocess.check_output(
                    "vtysh " + "-d ospfd " + "-c \"show ip ospf vrf " + vrf + " route\"",
                    universal_newlines=True, shell=True)
            if len(ospfRoutesDump) > 0:
                    print("Routes Dump")
                    print("===========")
                    print(ospfRoutesDump)

            ospfLSDB = subprocess.check_output(
                    "vtysh " + "-d ospfd " + "-c \"show ip ospf vrf " + vrf + " database\"",
                    universal_newlines=True, shell=True)
            if len(ospfLSDB) > 0:
                    print("Link State Database")
                    print("===================")
                    print(ospfLSDB)

            ospfDbRouters = subprocess.check_output(
                    "vtysh " + "-d ospfd " + "-c \"show ip ospf vrf " + vrf + " database " \
                    "router\"", universal_newlines=True, shell=True)
            if len(ospfDbRouters) > 0:
                    print("Detailed routers info")
                    print("=====================")
                    print(ospfDbRouters)

            ospfDbSummary = subprocess.check_output(
                    "vtysh " + "-d ospfd " + "-c \"show ip ospf vrf " + vrf + " database " \
                    "summary\"", universal_newlines=True, shell=True)
            if len(ospfDbSummary) > 0:
                    print("Database summary")
                    print("=====================")
                    print(ospfDbSummary)

            ospfRunning = subprocess.check_output(
                    "vtysh " + "-d ospfd " + "-c \"show running\"",
                    universal_newlines=True, shell=True)
            if len(ospfRunning) > 0:
                    print("show running-config")
                    print("=====================")
                    print(ospfRunning)

            ospfSelfOriginate = subprocess.check_output(
                    "vtysh " + "-d ospfd " + "-c \"show ip ospf vrf " + vrf + " database " \
                    "external self-originate\"",
                    universal_newlines=True, shell=True)
            if len(ospfSelfOriginate) > 0:
                    print("Self Originated")
                    print("=====================")
                    print(ospfSelfOriginate)


        # OSPFv3 commands.
        if (family == "all") or (family == "v6"):
            showOspf6Dump = subprocess.check_output(
                    "vtysh " + "-d ospf6d " + "-c \"show ipv6 ospf6 vrf " + vrf + "\"",
                    universal_newlines=True, shell=True)
            if len(showOspf6Dump) > 0:
                print("OSPFv3 dump")
                print("===========")
                print(showOspf6Dump)

            ospfInterfacesDump = subprocess.check_output(
                    "vtysh " + "-d ospf6d " + "-c \"show ipv6 ospf6 vrf " + vrf + \
                    " interface\"", universal_newlines=True, shell=True)
            if len(ospfInterfacesDump) > 0:
                    print("OSPFv3 Interfaces Dump")
                    print("======================")
                    print(ospfInterfacesDump)

            ospfNeighborsDump = subprocess.check_output(
                    "vtysh " + "-d ospf6d " + "-c \"show ipv6 ospf6 vrf " + vrf + \
                    " neighbor\"", universal_newlines=True, shell=True)
            if len(ospfNeighborsDump) > 0:
                    print("OSPFv3 Neighbors Dump")
                    print("=====================")
                    print(ospfNeighborsDump)

            ospfRoutesDump = subprocess.check_output(
                    "vtysh " + "-d ospf6d " + "-c \"show ipv6 ospf6 vrf " + vrf + \
                    " route\"", universal_newlines=True, shell=True)
            if len(ospfRoutesDump) > 0:
                    print("OSPFv3 Routes Dump")
                    print("==================")
                    print(ospfRoutesDump)

            ospfLSDB = subprocess.check_output(
                    "vtysh " + "-d ospf6d " + "-c \"show ipv6 ospf6 vrf " + vrf + \
                    " database\"", universal_newlines=True, shell=True)
            if len(ospfLSDB) > 0:
                    print("OSPFv3 Link State Database")
                    print("==========================")
                    print(ospfLSDB)

            ospfDbRouters = subprocess.check_output(
                    "vtysh " + "-d ospf6d " + "-c \"show ipv6 ospf6 vrf " + vrf + \
                    " database router\"", universal_newlines=True, shell=True)
            if len(ospfDbRouters) > 0:
                    print("OSPFv3 Detailed routers info")
                    print("============================")
                    print(ospfDbRouters)

            ospfRunning = subprocess.check_output(
                    "vtysh " + "-d ospf6d " + "-c \"show running\"",
                    universal_newlines=True, shell=True)
            if len(ospfRunning) > 0:
                    print("show ospf6d running-config")
                    print("==========================")
                    print(ospfRunning)

            ospfSelfOriginate = subprocess.check_output(
                    "vtysh " + "-d ospf6d " + "-c \"show ipv6 ospf6 vrf " + vrf + \
                    " database as-external self-originated\"",
                    universal_newlines=True, shell=True)
            if len(ospfSelfOriginate) > 0:
                    print("OSPFv3 Self Originated")
                    print("======================")
                    print(ospfSelfOriginate)


class ospfDumpNbrs(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (values):
            if len(values) == 1:
                params = {"family": values[0]}
            else:
                params = {"family": "all"}
        else:
            params = {"family": "all"}

        if (params["family"] == "all") or (params["family"] == "v4"):
            print("IPv4 Neighbors")
            print("==============")
            cmd = f"vtysh -d ospfd -c \"show ip ospf vrf all neighbor\""
            output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
            print(output)

        if (params["family"] == "all") or (params["family"] == "v6"):
            print("IPv6 Neighbors")
            print("==============")
            cmd = "vtysh -d ospf6d -c \"show ipv6 ospf6 vrf all neighbor\""
            output = subprocess.check_output(cmd, universal_newlines=True, shell=True)
            print(output)


class ospfDumpInfo(argparse.Action):
    def prep_ospf4_info(self, reply):
        cmd = "vtysh -d ospfd -c \"show ip ospf vrf all neighbor json\""
        output = subprocess.check_output(cmd, shell=True)
        output_str = output.decode('utf-8')
        if not output_str:
            return [];
        nbr_info = json.loads(output_str)

        ospf_info = []
        # edged returns information about only one neighbor.
        # Compare the JSON from edge and JSON from FRR to compose the final
        # JSON with multiple neighbors with the correct NSM status, nbr_addr
        # and nbr_id.
        # Hacky logic is required to keep the same behavior as in older
        # releases
        for e in reply["ospf_info"]:
            iface = e["interface"]
            segment = e["seg_id"]
            edged_nbr_addr = e.get("nbr_addr", None)
            frr_nbr_found = False
            for data in nbr_info.values():
                nbrs_dict = data["neighbors"]
                for router_id, nbrs in nbrs_dict.items():
                    for n in nbrs:
                        # FRR's output contains ifaceName in the output as
                        # "GE5:100:172.17.1.2 (iface:vlan:ip)". So for global
                        # segment the vlan part will NOT be present. Use this
                        # as a hack to differentiate between segments/vrfs.
                        frr_iface_toks = n["ifaceName"].split(":")
                        iface_toks = iface.split(":")
                        name = iface_toks[0]
                        vlan = None
                        frr_name = frr_iface_toks[0]
                        frr_vlan = None
                        if len(iface_toks) == 2:
                            vlan = iface_toks[1]
                        if len(frr_iface_toks) == 3:
                            frr_vlan = frr_iface_toks[1]
                        if (name != frr_name) or (vlan != frr_vlan):
                            continue

                        if edged_nbr_addr and (edged_nbr_addr == n["address"]):
                            ospf_info.append(e)
                            frr_nbr_found = True
                            continue
                        new = e.copy()
                        new["nsm_status"] = n["nbrState"]
                        new["nbr_id"] = router_id
                        new["nbr_addr"] = n["address"]
                        ospf_info.append(new)
            # If the nbr is deleted, edged would return info that the
            # nbr state is Deleted. But FRR does NOT return the nbr at
            # all in the show ip ospf neigh cmd. Hence if this is the
            # case, we return the JSON returned by edged itself.
            #
            # TODO: This cannot be done for multiple neighbors as
            # edged assumes only one nbr per interface.
            if edged_nbr_addr and not frr_nbr_found:
                ospf_info.append(e)

        return ospf_info

    def prep_ospf6_info(self, reply):
        cmd = "vtysh -d ospf6d -c \"show ipv6 ospf6 vrf all neighbor json\""
        output = subprocess.check_output(cmd, shell=True)
        output_str = output.decode('utf-8')
        output_str = '[' + output_str.replace('}\n{', '},{') + ']'
        if not output_str:
            return []

        # edged returns information about only one neighbor.
        # Compare the JSON from edge and JSON from FRR to compose the final
        # JSON with multiple neighbors with the correct NSM status, nbr_addr
        # and nbr_id.
        # Hacky logic is required to keep the same behavior as in older
        # releases
        ospf6_info = []
        nbr_info = json.loads(output_str)
        for e in reply["ospf6_info"]:
            iface = e["interface"]
            added = False
            for info in nbr_info:
                nbrs = info["neighbors"]
                if not nbrs:
                    continue
                for n in nbrs:
                    if iface != n["interfaceName"]:
                        continue
                    new = e.copy()
                    new["nsm_status"] = n["state"]
                    new["nbr_id"] = n["neighborId"]
                    ospf6_info.append(new)
                    added = True
            # In case a nbr is deleted, show ipv6 ospf6 neigh cmd does
            # NOT show an entry (for the interface). But since we need to
            # show the local config, we add the entry from edged itself
            # into the final output.
            if not added:
                e["nsm_status"] = ""
                e["nbr_id"] = "0.0.0.0"
                ospf6_info.append(e)
        return ospf6_info

    def __call__(self, parser, namespace, values, option_string=None):
        if (values):
            if len(values) == 1:
                params = {"family": values[0]}
            else:
                params = {"family": "all"}
        else:
            params = {"family": "all"}

        reply = remote_server.ospfDumpInfo(**params)

        final = {}
        if (params["family"] == "all") or (params["family"] == "v4"):
            ospf_info = self.prep_ospf4_info(reply)
            final["ospf_info"] = ospf_info

        if (params["family"] == "all") or (params["family"] == "v6"):
            ospf6_info = self.prep_ospf6_info(reply)
            final["ospf6_info"] = ospf6_info
        print(json.dumps(final, sort_keys = True, indent = 2))

class advertiseBgpPrefix(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"advertise_bgp_prefix", "opt":values[0],
                    "action":values[1], "seg_id": values[2]}
        reply = remote_server.advertiseBgpPrefix(**params)
        output = []
        print(json.dumps(reply, sort_keys = True, indent = 2))

class advertiseBgp6Prefix(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"advertise_bgp6_prefix", "opt":values[0],
                    "action":values[1], "seg_id": values[2]}
        reply = remote_server.advertiseBgp6Prefix(**params)
        output = []
        print(json.dumps(reply, sort_keys = True, indent = 2))

class advertiseOspfPrefix(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"advertise_ospf_prefix", "opt":values[0], "action":values[1]}
        reply = remote_server.advertiseOspfPrefix(**params)
        output = []
        print(json.dumps(reply, sort_keys = True, indent = 2))

class nhtRegistrationDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1": values[0], "arg2": "all", "arg3": "all" }
        elif len(values) == 2:
            params = {"arg1": values[0], "arg2": values[1], "arg3": "all"}
        elif len(values) == 3:
            params = {"arg1": values[0], "arg2": values[1], "arg3": values[2]}
        else:
            params = {"arg1": "all", "arg2": "all", "arg3": "all"}

        reply = remote_server.nhtRegistrationDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        nht_regs = []
        nht_regs.append(["Address", "Netmask", "Next Hop ID", "Dst LogicalId", "Intf", "Sub IntfId", "Next Hop IP", "Reachability", "Clients", "SEG"])
        for entry in reply["nht_regs"]:
            sub_intf_id = str(entry["vc_sub_if_idx"])
            if sub_intf_id == "-1":
                sub_intf_id = "N/A"
            nht_regs.append([entry["addr"], entry["netmask"], entry["nh_id"], entry["logical_id"],
                            entry["intf"], sub_intf_id, entry["next_hop_ip"], entry["reachability"], entry["clients"], str(entry["segment_id"])])
        pretty_print_table(nht_regs)
        print("B - BGP, P - PIM, b - BFD")

class bgpLocalIpDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1":values[0], "arg2":"all"}
        elif len(values) == 2:
            params = {"arg1":values[0],"arg2":values[1]}
        else:
            params = {"arg1":"all","arg2":"all"}

        reply = remote_server.bgpLocalIpDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        local_ips = []
        local_ips.append(["Address", "Nbr Count", "SEG"])
        for entry in reply["local_ips"]:
            local_ips.append([entry["addr"], str(entry["neighbor_count"]), str(entry["segment_id"])])
        pretty_print_table(local_ips)


class tgwPeerRouteListDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1":values[0], "arg2":"all"}
        elif len(values) == 2:
            params = {"arg1":values[0],"arg2":values[1]}
        else:
            params = {"arg1":"all","arg2":"all"}

        reply = remote_server.tgwPeerRouteListDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        tgw_peer_routes = []
        tgw_peer_routes.append(["Address", "NSD Logical ID", "Intf","SEG"])
        for entry in reply["tgw_peer_routes"]:
            tgw_peer_routes.append([entry["addr"], entry["nvs_logical_id"],
                                        entry["intf"], str(entry["segment_id"])])
        pretty_print_table(tgw_peer_routes)

class bfdLocalIpDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"arg1":values[0],"arg2":values[1]}
        reply = remote_server.bfdLocalIpDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        local_ips = []
        local_ips.append(["Address", "Nbr Count", "SEG"])
        for entry in reply["local_ips"]:
            local_ips.append([entry["addr"],str(entry["neighbor_count"]),str(entry["segment_id"])])
        pretty_print_table(local_ips)

class bfd6LocalIpv6DebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"arg1":values[0],"arg2":values[1]}
        reply = remote_server.bfd6LocalIpv6DebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        local_ips = []
        local_ips.append(["Address", "Nbr Count", "SEG"])
        for entry in reply["local_ips"]:
            local_ips.append([entry["addr"],str(entry["neighbor_count"]),str(entry["segment_id"])])
        pretty_print_table(local_ips)

class getResolvedRouteDebug(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values[0] == "all":
            print("Invalid first argument; Please provide a valid IP for recursive NH resolution")
            return

        params = {"arg1":values[0],"arg2":values[1]}
        reply = remote_server.getResolvedRouteDebug(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        resolved_routes = []
        resolved_routes.append(["Address", "Resolved", "Nexthop IP", "Intf", "Level", "SEG"])
        for entry in reply["resolved_routes"]:
            resolved_routes.append([entry["addr"], entry["is_resolved"], entry["next_hop_ip"], entry["intf"], entry["level"], str(entry["segment_id"])])
        pretty_print_table(resolved_routes)

class addRoutes(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):

        params = {"arg1":values[0]}
        reply = remote_server.addRoutes(**params)

class delRoutes(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):

        params = {"arg1":values[0], "arg2":values[1]}
        reply = remote_server.delRoutes(**params)

class edgePeerInfoDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"edge_peers"}
        reply = remote_server.edgePeerInfoDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ipSlaDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ip_sla"}
        reply = remote_server.ipSlaDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class setIpSlaIcmpProbeSeqNo(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if len(values) < 1:
                print(json.dumps({"result":"not enough arguments"}))
                return
            if int(values[0]) < 1 or int(values[0]) > 65534:
                print(json.dumps({"result":"No Probe seq between 1 to 65534 is given"}))
                return
            params = {"probe_seq":int(values[0])}
            reply = remote_server.setIpSlaIcmpProbeSeqNo(**params)
            print(json.dumps(reply, sort_keys = True, indent = 2))
        else:
            print(json.dumps({"result":"No Probe seq between 1 to 65534 is given"}))

class gatewayDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"gateway_dump"}
        reply = remote_server.gatewayListDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class enableNetflow(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        import ast

        #This basically converts string of
        #list to list format. E.g "[1, 2, 3]" to
        #[1, 2, 3]
        ret = ast.literal_eval(values[0])
        params = {"collector":values[0], "port":int(values[1]), "source_interface":values[2]}
        reply = remote_server.enableNetflow(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class disableNetflow(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"disableNetflow"}
        reply = remote_server.disableNetflow(**params)

class interfaceDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"interface_dump"}
        reply = remote_server.interfaceDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class interfaceQueryAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"query_ifaces"}
        reply = remote_server.query_ifaces(**params)
        print(json.dumps({"result":"Interface will be queried within 60 seconds"}))

class toggleFlowAgerAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if len(values) < 1:
                print(json.dumps({"result":"not enough arguments"}))

            arg_val = int(values[0])
            if arg_val != 0 and arg_val != 1:
                print(json.dumps({"result":"first argument needs to be 0/1"}))
                return

            params = {"enabled": arg_val}
            for i in range(1,len(values)):
                if 'timer_interval_secs' in values[i]:
                    arg_val = values[i].split('=')[1]
                    params.update({'timer_interval_secs': int(arg_val)})
                elif 'idle_timeout_secs' in values[i]:
                    arg_val = values[i].split('=')[1]
                    params.update({'idle_timeout_secs': int(arg_val)})

            reply = remote_server.toggleFlowAger(**params)
            print(json.dumps(reply))
        else:
            print(json.dumps({"result":"no input given"}))

class edgeDeleteTunnel(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"vceid":values[0]}
        print(params)
        reply = remote_server.de2eDeleteTunnel(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class edgeCreateTunnel(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"vceid":values[0]}
        print(params)
        reply = remote_server.de2eCreateTunnel(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class edgeDumpDe2eList(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"de2e_dump", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return
        print(params)
        reply = remote_server.de2eDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        peers = []
        peers.append(["Peer", "Name", "Initiator", "Now", "Last Update", "Rx Bytes", "Rx Bytes Last", "Tx Bytes","Tx Bytes Last"])
        for p in reply:
            peers.append([p['vceid'], p['peer_name'], str(p['initiator']),str(p['now']), str(p['last_update']), str(p['rx']), str(p['rx_last']), str(p['tx']), str(p['tx_last'])])
        pretty_print_table(peers)

class mallocTrim(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"run_malloc_trim"}
        reply = remote_server.mallocTrim(**params)

class mallocStats(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"run_malloc_stats"}
        reply = remote_server.mallocStats(**params)

class memoryDebugDump(argparse.Action):
    def readable_mem(self, bytes):
        mem = ""
        if bytes >> 20:
            mem += str(bytes >> 20) + "MB"
        elif bytes >> 10:
            mem += str(bytes >> 10) + "KB"
        else:
            mem += str(bytes)
        return mem

    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"memory_dump"}
        reply = remote_server.memoryDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        objs = []
        pre_allocated_mem = 0
        allocated_on_demand = 0
        total_mem = 0
        obj = ["Object Name", "Objects In-Use", "Bytes In-Use",
                "Pre-Allocated Objects", "Pre-Allocated Bytes", "Overhead"]
        objs.append(obj)
        for r in reply:
            if not r["count"] and not r["pre_allocated_count"]:
                continue
            obj = [str(r["name"]), str(r["count"]), self.readable_mem(r["bytes"]),
                str(r["pre_allocated_count"]), self.readable_mem(r["pre_allocated_bytes"]),
                self.readable_mem(r["overhead_bytes"])]
            objs.append(obj)
            if r["pre_allocated_bytes"]:
                pre_allocated_mem += r["pre_allocated_bytes"]
            else:
                allocated_on_demand += r["bytes"]
            if (r["pre_allocated_bytes"] and (r["bytes"] > r["pre_allocated_bytes"])):
                allocated_on_demand += r["bytes"] - r["pre_allocated_bytes"]
            allocated_on_demand += r["overhead_bytes"]
        pretty_print_table(objs)

        print("-" * 50)
        print("System Level Memory Statistics")
        print("-" * 50)
        print("Pre-Allocated Memory: " + self.readable_mem(pre_allocated_mem))
        print("Allocated On-Demand:  " + self.readable_mem(allocated_on_demand))
        print("Total Memory In-use:  " + self.readable_mem(pre_allocated_mem+allocated_on_demand))
        print("-" * 50)


class udpHolePunchingDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"udp_hole_punching"}
        reply = remote_server.udpHolePunchingDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class dpdkBondDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dpdk_bond_dump", "intf": values[0]}
        reply = remote_server.dpdkBondDump(**params)
        ports = []
        ports.append(["PCI", "Port", "Link"])
        for p in reply:
            ports.append([p['name'], str(p['port']), str(p['link'])])
        pretty_print_table(ports)

class dpdkPortsDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dpdk_ports_dump"}
        if values:
            params['name'] = values[0]
        reply = remote_server.dpdkPortsDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        ports = []
        fields = ['name', 'type', 'port', 'link', 'ignore', 'strip', 'speed',
                  'duplex', 'autoneg', 'driver', 'num_txq', 'txq_size', 'num_rxq', 'rxq_size']
        ports.append(fields)
        for p in reply:
            port = [ str(p[f]) for f in fields ]
            ports.append(port)
        pretty_print_table(ports)

class dpdkXstatsDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "xstats" }
        if values and values[-1] == "reset":
            params['reset'] = 1
            values = values[0:-1]
        if values:
            params['name'] = values[0]
        reply = remote_server.dpdkXstatsDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class cryptoTestAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"path":values[0]}
        reply = remote_server.crypto_test(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class configureNsdBgpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"configure_nsd_bgp"}
        if values and "nsd_static" in values:
            params["nsdStatic"] = 1

        reply = remote_server.configureNsdBgp(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class setStaleRouteTimeout(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"timeout":int(values[0])}
        reply = remote_server.setStaleRouteTimeout(**params)

class dbgPrRegRefresh(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"gwid":values[0],"peerid":values[1]}
        reply = remote_server.dbgPrRegRefresh(**params)

class clusterInfoDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"cluster_info"}
        reply = remote_server.clusterInfoDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class clusterStaticRouteDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"arg1":values[0], "arg2":"all", "arg3":"all", "arg4":"all"}
        elif len(values) == 2:
            params = {"arg1":values[0],"arg2":values[1], "arg3":"all", "arg4":"all"}
        elif len(values) == 3:
            params = {"arg1":values[0],"arg2":values[1], "arg3":values[2], "arg4":"all"}
        elif len(values) == 4:
            params = {"arg1":values[0],"arg2":values[1], "arg3":values[2], "arg4":values[3]}
        else:
            params = {"arg1":"all","arg2":"all","arg3":"all","arg4":"all"}

        params.update({"timeout_ms": get_timeout_ms(namespace) // 10,
                       "limit": get_entry_limit(namespace)})

        reply = remote_server.clusterStaticRouteDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        truncated = reply["truncated"]
        del reply["truncated"]

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            notify_truncated_output(truncated)
            return

        routes = []
        routes.append(["Address", "Netmask", "Type", "Gateway", "Next Hop ID", "Dst LogicalId",
                       "Metric", "Preference", "Flags", "Vlan", "Intf", "MTU", "SEG"])
        for entry in reply["routes"]:
            vlan_id = str(entry["vlan_id"])
            if vlan_id == "524287":
                vlan_id = "N/A"
            routes.append([entry["addr"], entry["netmask"], entry["type"], entry["gateway"],
                           entry["nhId"], entry["logicalId"], str(entry["metric"]),
                           str(entry["preference"]), str(entry["flags"]), vlan_id, entry["intf"],
                           entry["mtu"], str(entry["segment"])])
        pretty_print_table(routes)
        legend_str = "P - PG, D - DCE, L - LAN SR, C - Connected, O - External, W - WAN SR, "\
                     "S - SecureEligible, R - Remote, s - self, r - recursive, H - HA, "\
                     "m - Management, v - ViaVeloCloud, A - RouterAdvertisement, "\
                     "c - CWS, a - RAS"
        print(legend_str)
        notify_truncated_output(truncated)

class clusterRebalanceHub(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"rebalance_type": values[0]}
        reply = remote_server.clusterRebalanceHub(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class firewallLocalLogging(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"logging_enabled": values[0]}
        reply = remote_server.firewallLocalLogging(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class routeInitReqAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            params = {"debug":"reinit","arg1":values[0]}
        else:
            params = {"debug":"reinit","arg1":"all"}
        reply = remote_server.routeInitReq(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class getHealthReport(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "edged_get_health_report"}
        monitors = monitor.base.MonitorSet()
        monitors.add(monitor.cpu.CpuUsageMonitor())
        monitors.add(monitor.cpu.CpuLoadMonitor())
        monitors.add(monitor.mem.MemMonitor())
        faultmon = monitors.oneshotlist()
        cpu_load=format(faultmon["CPU.load"]).split(",")
        cpu60s = float(format(cpu_load[0][1:]))
        cpu60s = ("%.1f" % cpu60s)
        cpu300s = float(format(cpu_load[1][1:]))
        cpu300s = ("%.1f" % cpu300s)
        reply = remote_server.healthReport(**params)
        reply["cpu_60s_avg_pct"] = cpu60s
        reply["cpu_300s_avg_pct"] = cpu300s
        reply["edged_mem_usage_pct"] = faultmon["MEM.percent"]
        reply["cpu_usage_percent"] = faultmon["CPU.usage"]
        print(json.dumps(reply, sort_keys = True, indent = 2))

class rmsgReopen(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"edge_id":values[0]}
        reply = remote_server.rmsgReopen(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class edgeListDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"edge_list_dump"}
        reply = remote_server.edgeListDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["Name", "LogicalId", "ProfileId"])
        for p in reply:
            output.append([p['name'], str(p['logical_id']), str(p['profile_id'])])
        pretty_print_table(output)

class edgeClusterDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"edge_cluster_table"}
        reply = remote_server.edgeClusterDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["VCE-ID", "ClusterId", "Dir"])
        for p in reply:
            output.append([str(p['vce_id']), str(p['cluster_id']), str(p['direction'])])
        pretty_print_table(output)

class clusterEdgeDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"cluster_edge_table"}
        reply = remote_server.clusterEdgeDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class profileDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"profile_dump"}
        reply = remote_server.profileDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vcrpReopen(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"edge_id":values[0]}
        reply = remote_server.vcrpReopen(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class segmentDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:

            if (values[0] == "vpn"):
                params = {"debug":"segment_dump"}
                reply = remote_server.vpnsegmentDump(**params)
                print(json.dumps(reply, sort_keys = True, indent = 2))
            elif (values[0] == "gateway"):
                params = {"debug":"segment_dump"}
                reply = remote_server.gwsegmentDump(**params)
                print(json.dumps(reply, sort_keys = True, indent = 2))
            elif (values[0] == "controller"):
                params = {"debug":"segment_dump"}
                reply = remote_server.ctrlsegmentDump(**params)
                print(json.dumps(reply, sort_keys = True, indent = 2))
        else:
            params = {"debug":"segment_dump"}
            reply = remote_server.segmentDump(**params)
            print(json.dumps(reply, sort_keys = True, indent = 2))

class mcrDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"mcr_dump"}
        reply = remote_server.mcrDebugDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["Segment", "Source", "Group", "IIF", "OIL"])
        for entry in reply:
            output.append([str(entry["seg"]), entry["src"], entry["grp"], entry["iif"], entry["oil"]])
        pretty_print_table(output)

class vpnTestAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"seg":values[0]}
        reply = remote_server.vpnTestAction(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class nvsListAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"nvs_list"}
        reply = remote_server.nvsListDebugDump(**params)
        ipsec_flag = None
        gre_flag = None

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        ipsec_output = []
        gre_output = []

        for entry in reply:
            if entry["tunneling_protocol"] == "GRE":
                gre_output.append([entry["name"], entry["destination"], entry["link"], \
                                    entry["tunneling_protocol"], entry["state"], \
                                    entry["l7_state"], entry["ipsec_tunnel_id"], \
                                    entry["local_public_ip"], entry["nvs_ip"], \
                                    entry["routing"], str(entry["segmentId"])])
                gre_flag = True
            else:
                ipsec_output.append([entry["name"], entry["destination"], entry["link"], \
                                    entry["tunneling_protocol"], entry["state"], \
                                    entry["fwd_state"], \
                                    entry["l7_state"],entry["ipsec_tunnel_id"], \
                                    entry["local_public_ip"], entry["nvs_ip"], \
                                    entry["routing"], str(entry["segmentId"])])
                ipsec_flag = True

        if ipsec_flag:
            ipsec_title = []
            ipsec_title.append(["Name","Destination","Link","Protocol","State",
                               "Forwarding State","L7 State","Cookie",
                               "Source IP","Server IP","Policy","Segment"])
            ipsec_title.extend(ipsec_output)
            pretty_print_table(ipsec_title)
        if gre_flag:
            gre_title = []
            gre_title.append(["Name","Destination","Link","Protocol","State",
                             "L7 State","Tunnel ID","Source IP","Server IP",
                             "Policy","Segment"])
            gre_title.extend(gre_output)
            if ipsec_flag:
                print(" ")
            pretty_print_table(gre_title)



class l7HealthCheckListAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"l7_list"}
        reply = remote_server.l7HealthCheckDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class l7HealthCheckReportAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"segmentId": int(values[0]), "nvsLogicalId": values[1],
                  "linkLogicalId": values[2], "destId": int(values[3]),
                  "l7_success": int(values[4]), "rtt_ms": int(values[5])}
        reply = remote_server.l7HealthCheckReport(**params)

class l7HealthCheckTblAddAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"seg_id": int(values[0]), "dst_ip": values[1], "nvs_logical_id": values[2],
                  "enterprise_logical_id":values[3],
                  "nvs_ip": values[4], "dst_port":int(values[5])}
        reply = remote_server.l7HealthCheckTblInsert(**params)

class l7HealthCheckTblDelAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"seg_id": int(values[0]), "dst_ip": values[1],
                  "dst_port":int(values[2])}
        reply = remote_server.l7HealthCheckTblDelete(**params)

class l7HealthCheckTblDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"l7_health_dump"}
        reply = remote_server.l7HealthCheckTblDump(**params)
        reply = reply["health_check_dump"]
        print(json.dumps(reply, sort_keys = True, indent = 2))

class l7HealthCheckTblFlushAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"l7_health_tbl_flush"}
        reply = remote_server.l7HealthCheckTblFlush(**params)

class linkStateUp(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"linkStateUp", "intf": values[0]}
        reply = remote_server.setLinkState(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class linkStateDown(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"linkStateDown", "intf": values[0]}
        reply = remote_server.setLinkState(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vnfDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        reply = remote_server.vnfStatus({})
        print(json.dumps(reply, sort_keys = True, indent = 2))

class radiusRoutedDebugDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        reply = remote_server.radiusRoutedDebugDump({})
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        print("====================== MAC Bypass Rules ====================")
        output = []
        output.append(["iface", "MAC", "Hits"])
        for entry in reply["radius"]:
            for bypass in entry["macBypassRules"]:
                output.append([entry["iface"], bypass["macAddress"], str(bypass["hits"])])
        pretty_print_table(output)
        print("====================== Known Clients ====================")
        output = []
        output.append(["iface", "MAC", "Age(ms)", "Last Check(ms)", "Flags", "Hits"])
        for entry in reply["radius"]:
            for client in entry["knownClients"]:
                output.append([entry["iface"], client["macAddress"], str(client["age"]),
                    str(client["lastCheck"]), client["flags"], str(client["hits"])])
        pretty_print_table(output)

class radiusLanDebugDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        reply = remote_server.radiusLanDebugDump({})
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        print("====================== MAC Bypass Rules ====================")
        output = []
        output.append(["iface", "MAC", "Hits"])
        for entry in reply["radius"]:
            for bypass in entry["macBypassRules"]:
                output.append([entry["iface"], bypass["macAddress"], str(bypass["hits"])])
        pretty_print_table(output)
        print("====================== Known Clients ====================")
        output = []
        output.append(["iface", "MAC", "Age(ms)", "Last Check(ms)", "Flags", "Hits"])
        for entry in reply["radius"]:
            for client in entry["knownClients"]:
                output.append([entry["iface"], client["macAddress"], str(client["age"]),
                    str(client["lastCheck"]), client["flags"], str(client["hits"])])
        pretty_print_table(output)

class dbgMcStateUp(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dbgMcStateUp", "seg_id": values[0]}
        reply = remote_server.setDbgMcState(**params)
        try:
            mc_def_route = subprocess.check_output("route " + "add " +
                                    "-net " + "224.0.0.0/4 " + "dev " + "vce1",
                                    universal_newlines=True, shell=True)
        except:
            print("")
        print(json.dumps(reply, sort_keys = True, indent = 2))

class dbgMcStateDown(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dbgMcStateDown", "seg_id": values[0]}
        reply = remote_server.setDbgMcState(**params)
        try:
            mc_def_route = subprocess.check_output("route " + "del " +
                                    "-net " + "224.0.0.0/4 " + "dev " + "vce1",
                                    universal_newlines=True, shell=True)
        except:
            print("")
        print(json.dumps(reply, sort_keys = True, indent = 2))

class portScreenDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"port_screen"}
        reply = remote_server.portScreenDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class pingAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"src_ip": values[0], "dst_ip": values[1], "seg_id": values[2]}
        reply = remote_server.ping_test(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class denylistTblDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"denylist_dump"}
        reply = remote_server.denylistTblDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        print("Stateful Firewall Denylisting : IPv4 : %s" \
              %("Enabled" if reply["enabled"] else "Disabled"))
        print("                                IPv6 : %s" \
              %("Enabled" if reply["enabled_v6"] else "Disabled"))
        print("====================== SOURCE-IP LIST ====================")
        denylist_table = []
        denylist_table.append(["SOURCE-IP", "EXPIRES IN(sec)"])
        for entry in reply["denylist_ips"]:
            denylist_table.append([entry["source_ip"], str(entry["ttl"])])

        pretty_print_table(denylist_table)

class halfopenDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"halfopenDump"}
        reply = remote_server.halfopenDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        print("Stateful Firewall Halfopen Limit : IPv4 : %s" \
              %("Enabled" if reply["enabled"] else "Disabled"))
        print("                                   IPv6 : %s" \
              %("Enabled" if reply["enabled_v6"] else "Disabled"))
        print("====================== DESTINATION-IP LIST ====================")
        halfopen_table = []
        halfopen_table.append(["DESTINATION-IP", "COUNT"])
        for entry in reply["dest_ips"]:
            halfopen_table.append([entry["dest_ip"], str(entry["count"])])

        pretty_print_table(halfopen_table)

class trafficGeneratorAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        config_file_path = "/opt/vc/etc/traff_gen.json"
        print("Loading parameters from {0}".format(config_file_path))

        try:
            with open(config_file_path) as args_file:
                params = json.load(args_file)
        except IOError:
            print("Error: could not find config file {0}".format(config_file_path))
            return

        if params["runtime"] <= 0:
            print("Error: runtime must be greater than 0")
        elif USER_TIMEOUT_SECS <= params["runtime"]:
            print("Error: configured timeout must be greater than the desired runtime")
            print("       Re-run the program with [--timeout TIMEOUT SECONDS]")
            return

        reply = remote_server.trafficGenerator(**params)
        print("\nResult: {0}".format(json.dumps(reply, sort_keys = True, indent = 2)))

class segNatDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"segment_nat_dump"}
        reply = remote_server.segNatTableDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        seg_nat_table = []
        seg_nat_table.append(["AppName", "SegmentId", "CollectorIP", "DstPort", "Proto", "SourceIP", "SourceInterface", "InterfaceSelection", "TxCount", "RxCount"])
        for entry in reply:
            seg_nat_table.append([entry["app_name"], str(entry["segment_id"]), entry["dst_ip"], str(entry["dport"]), entry["proto"], entry["source_ip"], entry["source_interface"], entry["iface_selection"], str(entry["tx_hits"]), str(entry["rx_hits"])])

        pretty_print_table(seg_nat_table)

class nyansaEpNatDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"nyansa_ep_nat_dump"}
        reply = remote_server.nyansaEpNatDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        nyansa_ep_nat_table = []
        nyansa_ep_nat_table.append(["EndPontIP", "DstPort", "SourceIP", "SourceInterface"])
        for entry in reply:
            nyansa_ep_nat_table.append([entry["dst_ip"], str(entry["dport"]),
                                        entry["source_ip"], entry["source_interface"]])

        pretty_print_table(nyansa_ep_nat_table)

class loadLocalConfig(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "load_local_config"}
        reply = remote_server.loadLocalConfig(**params)

class suricataStatsDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "suricata_get_stats"}
        reply = remote_server.suricataStatsDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class suricataConfigDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "suricata_get_startup_param"}
        reply = remote_server.suricataConfigDump(**params)
        if "Error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        sc_entries=[]
        sc_entries.append(["Attribute", "value"])
        for entry in reply["suricata_startup_param"]:
            sc_entries.append([entry["param_name"],entry["value"]])
        pretty_print_table(sc_entries)

class segNatAddAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"app_id": int(values[0]), "seg_id": int(values[1]), "dst_ip": values[2], "dport": int(values[3]), "proto": values[4], "sourceInterface": values[5]}
        reply = remote_server.segNatTableAdd(**params)

class segNatFlushAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"app_name": values[0]}
        reply = remote_server.segNatTableFlush(**params)

class dynBwConfigDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"dynamic_bw"}
        reply = remote_server.dynBwConfigDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class ppDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values[0] == "tx":
            side = 1;
        elif values[0] == "rx":
            side = 0;
        else:
            print(json.dumps({"result":"Invalid Argument"}))
            return
        params = {"side":side,"peer_id":values[1]}
        reply = remote_server.ppDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class cbhDebug(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"cbh"}
        reply = remote_server.cbhDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

#sort help in alphabetical order
class HelpSorterClass(argparse.HelpFormatter):
    def add_arguments(self, actions):
        actions = sorted(actions, key=attrgetter('option_strings'))
        super(HelpSorterClass, self).add_arguments(actions)

class setUnsetCpuMetric(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1 and values[0] == "reset":
            params = {"reset":"cpumetric_reset"}
            reply = remote_server.cpumetricdebug(**params)
            print(json.dumps(reply, sort_keys = True, indent = 2))
        elif len(values) == 2 and values[0] == "set" and values[1].isdigit():
            params = {"set": int(values[1])}
            reply = remote_server.cpumetricdebug(**params)
            print(json.dumps(reply, sort_keys = True, indent = 2))
        else:
            params = {"dump":"cpumetricdump"}
            reply = remote_server.healthReport(**params)
            print(json.dumps(reply, sort_keys = True, indent = 2))

class haWanHbSuppress(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
         params = {"wan_hb_suppress": int(values[0])}
         reply = remote_server.haWanHbSuppress(**params)
         print(json.dumps(reply, sort_keys = True, indent = 2))

class displayOfcConfig(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 1:
            params = {"addressType": values[0]}
            if (values[0] != 'v4') and (values[0] != 'v6'):
                print("Argument can be only v4 or v6!")
                return
            reply = remote_server.displayOfcConfig(**params)
            if reply:
                self.print_ofc_configs(reply)
        else:
            params = {"addressType": "v4"}
            reply = remote_server.displayOfcConfig(**params)
            if reply:
                self.print_ofc_configs(reply)
            params["addressType"] = "v6"
            reply = remote_server.displayOfcConfig(**params)
            if reply:
                print("\nv6 configs:")
                self.print_ofc_configs(reply)

    def print_ofc_configs(self, reply):
        print("DCC: "+ str(reply["DCC"]))
        print("NSD OFC: "+ str(reply["NSD OFC"]))
        print("RefreshVer: "+  str(reply["RefreshVersion"]))
        print("\nEdge")
        for k1, v1, in reply["Edge"].items():
            print("\t" + str(k1) + ":" + str(v1))
        print("Hub")
        for k1, v1 in list(reply["Hub"].items()):
            print("\t" + str(k1) + ":" + str(v1))
        print("NSD")
        for k1, v1 in list(reply["NSD"].items()):
            print("\t" + str(k1) + ":" + str(v1))
        print("Preference")
        for k1, v1 in list(reply["Preference"].items()):
            print("\t" + str(k1) + ":" + str(v1))

class cwsPolicyDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"cwsPolicy":"all"}
        reply = remote_server.cwsPolDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["Logical Id", "CWS Policy Name", "CWS Policy ID"])

        cws_policies = reply["cws_pol"]
        for cws_pol in cws_policies:
            output.append([str(cws_pol["log_id"]), str(cws_pol["cws_pol_name"]),
                             str(cws_pol["cws_pol_id"])])
        if len(output) > 0:
            pretty_print_table(output)

class addressGroupDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug": "address_groups"}
        if values:
            if len(values) > 1:
                print("""Invalid no.of arguments provided. Maximum no.of argument is 1.
                      usage: --address_groups [v4 | v6 | all]""")
                return
            if (len(values) == 1):
                 params.update({"ip_fam": values[0]})
        else:
            params.update({"ip_fam": "all"})
        reply = remote_server.addressGroupDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class portGroupDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"port_groups"}
        reply = remote_server.portGroupDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class linkModeDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"link_mode"}
        reply = remote_server.linkModeDebugDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class getVnfHaState(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {}
        params['debug'] = "get_vnf_ha_state"
        reply = remote_server.getVnfHaState(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class vnfHaSuppress(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {}
        params['vnf_ha_suppress'] = int(values[0])
        params['debug'] = "vnf_ha_suppress"
        reply = remote_server.vnfHaSuppress(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class sessionTableSummary(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"session_table_summary"}
        reply = remote_server.sessionTableSummary(**params)

        if "error" in reply or namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        session_table = []
        session_table.append(["ARP", "DHCP", "DNS", "EAP", "HTTP", "HL7",
                             "STANDARD", "TOTAL ACTIVE"])
        session_table.append([str(reply["arp_sessions"]), str(reply["dhcp_sessions"]),
                              str(reply["dns_sessions"]), str(reply["eap_sessions"]),
                              str(reply["http_sessions"]), str(reply["hl7_sessions"]),
                              str(reply["standard_sessions"]), str(reply["active_sessions"])])
        pretty_print_table(session_table)

        print("\nIdle Sessions: " + str(reply["idle_sessions"]))

class connectivityDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"connectivity_dump"}
        reply = remote_server.connectivityMacTblDump(**params)

        if "error" in reply or namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        connectivity_table = []
        connectivity_table.append(["MAC Address", "IP Address", "refcnt"])
        for entry in reply:
            connectivity_table.append([str(entry["client_mac"]),
                                       str(entry["client_ip"]),
                                       str(entry["refcnt"])])
        pretty_print_table(connectivity_table)

class ikeTunnelDebug(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ike_ptd"}
        if len(values) < 1:
            print("Insufficient Arguments. Refer --help.")
            return
        if values and "clear" in values:
            params["clear"] = 1
        else:
            if len(values) < 3:
                print("Insufficient Arguments for adding PTD. Refer --help.")
                return
            params = {"src_ip": values[0], "dst_ip": values[1], "level": int(values[2])}
        reply = remote_server.ikeTunnelDebug(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class perPeerDebug(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"ike_ppd"}
        if len(values) < 1:
            print("Insufficient Arguments. Refer --help.")
            return
        if values and "clear" in values:
            params["clear"] = 1
        else:
            if len(values) != 3:
                print("Invalid Arguments for adding Per Peer Debugging. Refer --help.")
                return
            params = {"cookie": values[0], "sip": values[1], "dip": values[2]}

        reply = remote_server.perPeerDebug(**params)
        print(json.dumps(reply, sort_keys=True, indent=2))

class ifaceDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "iface_dump" }
        for val in values:
            kv = val.split("=")
            k, v = kv[0], kv[1]
            if k in ["ifindex"]:
                v = int(v)
            params[k] = v
        reply = remote_server.ifaceDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        reply = reply["ifaces"]
        ifaces = []
        ifaces.append(["IfIndex", "Name (Descr)", "Driver", "State", "IP Addr",
                       "IPv6 Addr List", "Caps",
                       "Rx Packets/Pps", "Rx Bytes/Average", "Rx Dropped", "Rx Errors",
                       "Tx Packets/Pps", "Tx Bytes/Average", "Tx Dropped", "Tx Errors"])
        for iface in reply:
            name = str(iface["name"])
            if iface["netdev"]:
                name += "/" + iface["netdev"]
            if iface["descr"]:
                name += " (%s)" % iface["descr"]

            state = iface["oper_state"] + "/"
            state += "RUNNING" if iface["running"] == 1 else "STOPPED"

            ip_addr_list = [];
            ipv6_addr_list = []
            ip = iface.get("ip")
            if ip:
                pri_addr = ip["pri_addr"]
                pri_ip = pri_addr["addr"]
                pri_ip += "/%d" % ip_mask_to_prefix_len(pri_addr["mask"])
                ip_addr_list.append(pri_ip)
                sec_addr_list = ip.get("sec_addr_list")
                for sec_addr in sec_addr_list:
                    sec_ip = sec_addr["addr"]
                    sec_ip += "/%d" % ip_mask_to_prefix_len(sec_addr["mask"])
                    ip_addr_list.append(sec_ip)

                ipv6_info = ip.get("ip6_addr_list")
                for ipv6_entry in ipv6_info:
                    ipv6_addr_list.append(ipv6_entry["addr"] + '/' +
                               str(ipv6_entry["prefixlen"]))

            ifaces.append([str(iface["ifindex"]), name, iface["driver_name"],
                           state, ','.join(ip_addr_list),
                           ','.join(ipv6_addr_list), iface["capabilities"],
                           str(iface["rx_packets"]) + "/" + str(iface["rx_pps"]),
                           str(iface["rx_bytes"]) + "/" + str(iface["rx_avg_pktsize"]),
                           str(iface["rx_dropped"]), str(iface["rx_errors"]),
                           str(iface["tx_packets"]) + "/" + str(iface["tx_pps"]),
                           str(iface["tx_bytes"]) + "/" + str(iface["tx_avg_pktsize"]),
                           str(iface["tx_dropped"]), str(iface["tx_errors"])])

        pretty_print_table(ifaces)
        print("\nCaps: U/u - Rx/Tx UDP Cksum Offload, " \
              "I/i - Rx/Tx IP Cksum Offload, " \
              "R - Rx RSS Hash Offload")

class nd6QueueLimit(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) < 1:
            print("Insufficient Arguments")
            return

        params = {"debug": "queuelimit", "limit": int(values[0])}
        reply = remote_server.nd6NbrQueueLimit(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class dptSetProfileModeAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "mode" : values[0] }
        reply = remote_server.dptSetProfileMode(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class dptCoreStatsAction(argparse.Action):
    def cpu_usage(self, usage_ns, period_ns):
        if period_ns:
            return (usage_ns & 0xffffffffffffffff) * 100.0 / \
                   (period_ns & 0xffffffffffffffff)
        else:
            return 0.0

    def __call__(self, parser, namespace, values, option_string=None):
        params = {
            "core_id": \
                0xffffffff if values == "all" or not values else int(values)
        }
        reply = remote_server.dptCoreStats(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        core_id = 0 if values == "all" or not values else int(values)
        for core in reply:
            period_ns = core["period_ns"]
            idle_ns = core["idle_ns"]
            timer_ns = core["timer_ns"]
            task_ns = period_ns - timer_ns - idle_ns

            core["tasks"].sort(key=lambda s: s["total_ns"], reverse=True)
            core["timers"].sort(key=lambda s: s["total_ns"], reverse=True)

            flags = ""
            flags += "I" if core["io_core"] else "-"
            flags += "T" if core["tun_core"] else "-"
            flags += "F" if core["flow_core"] else "-"
            flags += "N" if core["net_sched_core"] else "-"
            flags += "L" if core["link_sched_core"] else "-"
            flags += "S" if core["link_select_core"] else "-"
            flags += "X" if core["excl_core"] else "-"
            cpuset = core["cpuset"]

            print("100.00%% Core %u: flags=%s, cpuset=0x%x" %
                      (core_id, flags, cpuset))
            print("   |--- %.2f%% Idle" % self.cpu_usage(idle_ns, period_ns))
            print("   |--- %.2f%% Tasks" % self.cpu_usage(task_ns, period_ns))
            for task in core["tasks"]:
                perc = "%.2f/%.2f%%" % \
                (self.cpu_usage(task["total_ns"], period_ns),
                 self.cpu_usage(task["total_ns"], task_ns))
                min = "min=%uns" % task["min_ns"]
                max = "max=%uns" % task["max_ns"]
                work = "work=%u/s" % task["work"]
                max_work = "max_work=%d" % (task["max_work"] & 0xffffffff)
                print("   |       |--- %-12s %-48s %-14s %-14s %-14s %s" %
                      (perc, task["name"], min, max, work, max_work))

            print("   |--- %.2f%% Timers" % self.cpu_usage(timer_ns, period_ns))
            for timer in core["timers"]:
                perc = "%.2f/%.2f%%" % \
                (self.cpu_usage(timer["total_ns"], period_ns),
                 self.cpu_usage(timer["total_ns"], timer_ns))
                min = "min=%uns" % timer["min_ns"]
                max = "max=%uns" % timer["max_ns"]
                hits = "hits=%u/s" % timer["hits"]
                print("           |--- %-12s %-48s %-14s %-14s %-14s %s" %
                      (perc, timer["name"], min, max, hits,
                       "periodical" if timer["periodical"] else "single"))

            core_id += 1

class cpusetAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        reply = remote_server.cpusetDump({})
        print(json.dumps(reply, sort_keys = True, indent = 2))

class dptSetMaxWorkAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {
            "core_id":  0xffffffff if values[0] == "all" else int(values[0]),
            "match": values[1],
            "max_work": int(values[2])
        }
        reply = remote_server.dptSetMaxWork(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))


class dptYieldAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        reply = {}
        if len(values):
            min_idle_yield_us = 0
            max_idle_yield_us = 100
            idle_yield_pattern = 1
            if values[0] == "adaptive":
                if len(values) > 1 and values[1]:
                    min_idle_yield_us = int(values[1])
                if len(values) > 2 and values[2]:
                    max_idle_yield_us = int(values[2])
                idle_yield_pattern = 1
            elif values[0] == "legacy":
                idle_yield_pattern = 0
                min_idle_yield_us = 10
                max_idle_yield_us = 10
            elif values[0] == "linear":
                if len(values) > 1 and values[1]:
                    min_idle_yield_us = int(values[1])
                if len(values) > 2 and values[2]:
                    max_idle_yield_us = int(values[2])
                idle_yield_pattern = 2
            elif values[0] == "log":
                if len(values) > 1 and values[1]:
                    min_idle_yield_us = int(values[1])
                if len(values) > 2 and values[2]:
                    max_idle_yield_us = int(values[2])
                idle_yield_pattern = 1
            else:
                print("Invalid command")
                return

            if min_idle_yield_us < 0 or min_idle_yield_us > 150:
                print("min_idle_yield_us out of range(0..150)")
                return

            if max_idle_yield_us < 0 or max_idle_yield_us > 150:
                print("max_idle_yield_us out of range(0..150)")
                return

            params = {"min_idle_yield_us" : min_idle_yield_us,
                      "max_idle_yield_us" : max_idle_yield_us,
                      "idle_yield_pattern" : idle_yield_pattern }
            reply = remote_server.dptYieldConfig(**params)
        else:
            params = {"debug" : "dptYieldStatus"}
            reply = remote_server.dptYieldStatus(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))


def print_fdisp_flows(reply, namespace):
    if namespace.verbose:
        print(json.dumps(reply, sort_keys = True, indent = 2))
        return

    flows = []
    flows.append(["Core Id", "Type", "IfIndex", "Proto", "Discr", "Src IP",
                  "Src Port", "Dst IP", "Dst Port", "TOS", "Paused", "Refs",
                  "Size", "Priv Size", "Hits", "Drops", "Exceptions",
                  "Actions"])
    for flow in reply["flows"]:
        actions = []
        for action in flow["actions"]:
            actions.append(action["name"])
        actions = ", ".join(actions)

        flows.append([str(flow["cid"]), str(flow["type"]),
                      str(flow["ifindex"]), str(flow["protocol"]),
                      "%u/%u" %
                      (flow["discr_type"], flow["discr"] & 0xffffffff),
                      flow["src_ip"], str(flow["src_port"]),
                      flow["dst_ip"], str(flow["dst_port"]),
                      str(flow["ip_tos"]) + ("*" if flow["match_tos"] else ""),
                      "Y" if flow["paused"] else "N",
                      "%u/%u" % (flow["refs"], flow["local_refs"]),
                      str(flow["size"]), str(flow["priv_size"]),
                      str(flow["hits"]), str(flow["drops"]),
                      str(flow["exceptions"]), actions])

    pretty_print_table(flows)

class flowDispatcherFlowDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "cid_pos": 0, "bkt_pos": 0 }
        for val in values:
            if val == "v4":
                params.update({"ipversion":4})
            elif val == "v6":
                params.update({"ipversion":6})
            else:
                kv = val.split("=")
                k, v = kv[0], kv[1]
                if k in ["src_ip", "dst_ip"]:
                    if "." in v:
                        v = "::ffff:" + v
                elif k not in ["type"]:
                    v = int(v)
                params[k] = v

        while params["cid_pos"] != -1:
            reply = remote_server.flowDispatcherFlowDump(**params)
            if "error" in reply:
                print(json.dumps(reply, sort_keys = True, indent = 2))
                return
            print_fdisp_flows(reply, namespace);
            params["cid_pos"] = reply["cid_pos"]
            params["bkt_pos"] = reply["bkt_pos"]

class flowDispatcherSetProfileModeAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "mode" : values[0] }
        reply = remote_server.flowDispatcherSetProfileMode(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class flowDispatcherDumpAction(argparse.Action):
    def cpu_usage(self, usage_ns, period_ns):
        if period_ns:
            return (usage_ns & 0xffffffffffffffff) * 100.0 / \
                   (period_ns & 0xffffffffffffffff)
        else:
            return 0.0

    def __call__(self, parser, namespace, values, option_string=None):
        params = {
            "core_id": \
                0xffffffff if values == "all" or not values else int(values)
        }
        reply = remote_server.flowDispatcherDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        for disp in reply:
            period_ns = disp["period_ns"]
            real_period_ns = disp["real_period_ns"]
            disp["actions"].sort(key=lambda s: s["total_ns"], reverse=True)
            disp["exceptions"].sort(key=lambda s: s["total_ns"], reverse=True)

            action_ns = 0
            for action in disp["actions"]:
                action_ns += action["total_ns"]

            exception_ns = 0
            for ex in disp["exceptions"]:
                exception_ns += ex["total_ns"]

            print("100.00%% Core %u: flows=%u, stale-flows=%u, queued-pkts=%u (max %u)" %
                  (disp["cid"], disp["flow_cnt"], disp["stale_flow_cnt"],
                   disp["queued_pkts"], disp["max_queued_pkts"]))
            print("   |--- %.2f%% Actions" % self.cpu_usage(action_ns, period_ns))
            for action in disp["actions"]:
                perc = "%.2f%%" % self.cpu_usage(action["total_ns"], period_ns)
                name = "%3u: %s" % (action["aid"], action["name"])
                min = "min=%uns" % action["min_ns"]
                max = "max=%uns" % action["max_ns"]
                hits = "hits=%u/s" % (action["hits"] * 1000000000 / real_period_ns)
                drops = "drops=%u/s" % (action["drops"] * 1000000000 / real_period_ns)
                print("   |       |--- %-18s %-48s %-15s %-15s %-14s %-14s" %
                      (perc, name, min, max, hits, drops))

            print("   |--- %.2f%% Exceptions" % self.cpu_usage(exception_ns, period_ns))
            for ex in disp["exceptions"]:
                perc = "%.2f%%" % self.cpu_usage(ex["total_ns"], period_ns)
                name = "%3u: %s" % (ex["code"], ex["name"])
                min = "min=%uns" % ex["min_ns"]
                max = "max=%uns" % ex["max_ns"]
                hits = "hits=%u/s" % (ex["hits"] * 1000000000 / real_period_ns)
                handled = "handled=%u/s" % (ex["handled"] * 1000000000 / real_period_ns)
                print("           |--- %-18s %-48s %-15s %-15s %-14s %-14s" %
                      (perc, name, min, max, hits, handled))

                ex["handlers"].sort(key=lambda s: s["handled_total_ns"] +
                                    s["unhandled_total_ns"], reverse=True)
                for hdlr in ex["handlers"]:
                    total_ns = hdlr["handled_total_ns"] + hdlr["unhandled_total_ns"]
                    perc = "%.2f/%.2f%%" % \
                        (self.cpu_usage(total_ns, period_ns),
                         self.cpu_usage(total_ns, ex["total_ns"]))
                    min = "min=%uns/%uns" % (hdlr["handled_min_ns"], hdlr["unhandled_min_ns"])
                    max = "max=%uns/%uns" % (hdlr["handled_max_ns"], hdlr["unhandled_max_ns"])
                    hits = "hits=%u/s" % (hdlr["hits"] * 1000000000 / real_period_ns)
                    handled = "handled=%u/s" % (hdlr["handled"] * 1000000000 / real_period_ns)
                    print("           |       |--- %-12s    %-43s %-15s %-15s %-14s %-14s" %
                          (perc, hdlr["name"], min, max, hits, handled))

            print("")

class flowDispatcherHashTableStatsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {
            "core_id": \
                0xffffffff if values == "all" or not values else int(values)
        }
        reply = remote_server.flowDispatcherHashTableStats(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class rssHashCalcAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {
            "src_ip": "::ffff:" + values[0] if "." in values[0] else values[0],
            "src_port": int(values[1]),
            "dst_ip": "::ffff:" + values[2] if "." in values[2] else values[2],
            "dst_port": int(values[3]),
            "proto": int(values[4])
        }
        reply = remote_server.rssHashCalc(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        print("Hash: 0x%x, io_core: %d, tun_core: %d, flow_core: %d" % \
                (reply["hash"] & 0xffffffff, reply["io_core"],
                 reply["tun_core"], reply["flow_core"]))

class selfIpDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"self_ip_dump", "ipversion":0}
        if (values):
            if values[0] == "v4":
                params.update({"ipversion":4})
            elif values[0] == "v6":
                params.update({"ipversion":6})
            elif values[0] != "all":
                print("Invalid addr type [v4 | v6 | all]")
                return

        reply = remote_server.selfIpTableDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        self_ip_entry = []
        self_ip_entry.append(["ip_addr", "vc_if_index", "vlan_id"])
        for entry in reply:
            self_ip_entry.append([str(entry["ip_addr"]),
                                  str(entry["vc_if_index"]),
                                  str(entry["vlan_id"])])
        pretty_print_table(self_ip_entry)

class TopTable:
    class Col:
        def __init__(self, key, heading, src=None):
            self.key = key
            self.heading = heading
            self.src = src

    def __init__(self, col_descs, key=None):
        self.col_descs = col_descs
        self.key = key

    def get_key_from_heading(self, heading):
        for col in self.col_descs:
            if col.heading == heading:
                return col.key
        return None

    def print_table(self, entries, sort_key=None, limit=0xffffffff):
        table = [[]]
        for col in self.col_descs:
            heading = col.heading + ("*" if col.key == sort_key else "")
            table[0].append(heading)

        if sort_key is not None:
            entries.sort(reverse=True,
                         key=lambda x: (-1 if x[sort_key] == '-' else int(x[sort_key])))

        num_entries = 0;
        for e in entries:
            row = []
            for col in self.col_descs:
                val = e[col.key]
                if is_float(val):
                    val = int(round(val))
                if val == -1:
                    val = "-"
                row.append(str(val))

            table.append(row)
            num_entries += 1
            if limit and num_entries >= limit:
                break;

        pretty_print_table(table)
        sys.stdout.flush()

    def update_entries(self, entries, old_entries, elapsed_us):
        for e in entries:
            oe = old_entries.get(e[self.key])
            for col in self.col_descs:
                if col.src is None:
                    continue

                e[col.key] = col.src(e, oe, elapsed_us)

    @staticmethod
    def calc_rate(entry, old_entry, elapsed_us, key, mult=1, div=1):
        if old_entry is None:
            return -1

        diff = entry[key] - old_entry[key]
        return diff * 1000000 * mult / elapsed_us / div

class queueTopAction(argparse.Action):
    def __init__(self, **kwargs):
        super(queueTopAction, self).__init__(**kwargs)

        Col = TopTable.Col
        calc_rate = TopTable.calc_rate
        col_descs = [
            Col("name", "Name"),
            Col("len", "Length"),
            Col("drops", "Drops"),
            Col("drop_rate", "Drops/s", src=partial(calc_rate, key="drops")),
            Col("wmark", "Wmark"),
            Col("wmark_1min", "Wmark-1min"),
            Col("wmark_5min", "Wmark-5min"),
            Col("limit", "Limit"),
            Col("enq", "Enqueue"),
            Col("deq", "Dequeue"),
        ]
        self.table = TopTable(col_descs, "name")

    def __call__(self, parser, namespace, values, option_string=None):
        sort_key = self.table.get_key_from_heading(values)
        sort_key = "len" if sort_key is None else sort_key
        limit = get_entry_limit(namespace)
        limit = 25 if limit == 0 else limit

        try:
            old_queues = {}
            old_over_capacity_drops = -1
            old_sched_drops = -1
            old_timestamp_us = 0
            params = { "debug": "queue_top" }
            while True:
                reply = remote_server.queueTop(**params)
                if "Error" in reply:
                    print(json.dumps(reply, sort_keys = True, indent = 2))
                    return
                queues = reply["queues"]
                over_capacity_drops = reply["over_capacity_drops"]
                sched_drops = reply["sched_drops"]
                timestamp_us = reply["timestamp_us"]

                elapsed_us = timestamp_us - old_timestamp_us

                header = []
                header.append(["Pkts:", "total: %d" % reply["total_pkts"],
                               "free: %d (%.2f%%)" % (reply["free_pkts"],
                               reply["free_pkts"] * 100.0 / reply["total_pkts"]),
                               "locked-free: %d" % reply["locked_free_pkts"]])

                adm_ctrl_status = "" if reply["admission_ctrl_enabled"] else " (Disabled)"
                header.append(["Thresholds:", "critical: %d" % reply["crit_pkts"],
                               "admission-ctrl%s: %d" % (adm_ctrl_status,
                               reply["admission_ctrl_pkts"]), ""])

                over_capacity_drop_rate = "-"
                if old_over_capacity_drops != -1:
                    drops = over_capacity_drops - old_over_capacity_drops
                    over_capacity_drop_rate = str(drops * 1000000 / elapsed_us)

                sched_drop_rate = "-"
                if old_sched_drops != -1:
                    drops = sched_drops - old_sched_drops
                    sched_drop_rate = str(drops * 1000000 / elapsed_us)

                header.append(["Drops:", "over-capacity: %d (%s/s)" % \
                               (over_capacity_drops, over_capacity_drop_rate),
                               "sched: %d (%s/s)" % (sched_drops, sched_drop_rate),
                               ""])
                pretty_print_table(header, align_left=True)

                self.table.update_entries(queues, old_queues, elapsed_us)
                self.table.print_table(queues, sort_key, limit)
                print("")

                old_queues = { x[self.table.key] : x for x in queues }
                old_over_capacity_drops = over_capacity_drops
                old_sched_drops = sched_drops
                old_timestamp_us = timestamp_us
                time.sleep(2)
        except KeyboardInterrupt:
            pass

class sorDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (values):
            params = {"entr_log_id": "all", "node_id": values}
        else:
            params = {"entr_log_id": "all", "node_id": "all"}
        reply = remote_server.sorDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        sor_entries = []
        sor_header = ["Entr_ID", "Node_ID", "Transit", "Cluster", "Profile_ID", "D/R", \
        "Reachable", "Metric", "Uturn", "ToC", "ToU", "Uturn_Transit_Count"]
        sor_entries.append(sor_header)
        for data in reply["sor_entries"]:
            dlist = data['direct']
            rlist = data['relayed']
            for direct in dlist:
                toc = datetime.datetime.utcfromtimestamp(direct['toc']).\
                strftime('%Y-%m-%dT%H:%M:%S')
                tou = datetime.datetime.utcfromtimestamp(direct['tou']).\
                strftime('%Y-%m-%dT%H:%M:%S')
                uturn_count = str(len(direct['uturn_gw_list']))
                sor_entries.append([data['entr_id'], data['node_id'], \
                direct['transit'], direct['cluster'], direct['profile'], 'D', \
                direct['reachable'], str(direct['metric']), direct['uturn'], toc, \
                tou, uturn_count])
            for relayed in rlist:
                toc = datetime.datetime.utcfromtimestamp(relayed['toc']).\
                strftime('%Y-%m-%dT%H:%M:%S')
                tou = datetime.datetime.utcfromtimestamp(relayed['tou']).\
                strftime('%Y-%m-%dT%H:%M:%S')
                uturn_count = str(len(relayed['uturn_gw_list']))
                sor_entries.append([data['entr_id'], data['node_id'], \
                relayed['transit'], relayed['cluster'], relayed['profile'], 'R', \
                relayed['reachable'], str(relayed['metric']), relayed['uturn'], toc, \
                tou, uturn_count])
        pretty_print_table(sor_entries)

class sttDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if (values):
            params = {"entr_log_id": "all", "transit_log_id": values}
        else:
            params = {"entr_log_id": "all", "transit_log_id": "all"}
        reply = remote_server.sttDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        stt_entries = []
        stt_header = ["Entr_ID", "Transit_ID", "Node_ID", "Cluster", "Profile_ID", \
        "Reachable", "Metric", "Uturn", "ToC", "ToU"]
        stt_entries.append(stt_header)
        for data in reply["stt_entries"]:
            node_list = data['sor_nodes']
            for sor_node in node_list:
                toc = datetime.datetime.utcfromtimestamp(sor_node['transit']['toc']).\
                    strftime('%Y-%m-%dT%H:%M:%S')
                tou = datetime.datetime.utcfromtimestamp(sor_node['transit']['tou']).\
                    strftime('%Y-%m-%dT%H:%M:%S')
                stt_entries.append([data['entr_id'], data['transit_id'], \
                    sor_node['node_id'], sor_node['transit']['cluster'], \
                    sor_node['transit']['profile'], sor_node['transit']['reachable'], \
                    str(sor_node['transit']['metric']), sor_node['transit']['uturn'], toc, tou])
        pretty_print_table(stt_entries)

class de2eSubDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"de2eSubDump":"all"}
        reply = remote_server.de2eSubDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))
        return

class ifaceTopAction(argparse.Action):
    def __init__(self, **kwargs):
        super(ifaceTopAction, self).__init__(**kwargs)

        Col = TopTable.Col
        calc_rate = TopTable.calc_rate
        col_descs = [
            Col("display_name", "Name", src=self.get_name),
            Col("rx_pps", "Rx-PPS", src=partial(calc_rate, key="rx_packets")),
            Col("rx_kbps", "Rx-Kbps", src=partial(calc_rate, key="rx_bytes", div=125)),
            Col("rx_drop_rate", "Rx-Drops/s", src=partial(calc_rate, key="rx_dropped")),
            Col("rx_err_rate", "Rx-Errors/s", src=partial(calc_rate, key="rx_errors")),
            Col("tx_pps", "Tx-PPS", src=partial(calc_rate, key="tx_packets")),
            Col("tx_kbps", "Tx-Kbps", src=partial(calc_rate, key="tx_bytes", div=125)),
            Col("tx_drop_rate", "Tx-Drops/s", src=partial(calc_rate, key="tx_dropped")),
            Col("tx_err_rate", "Tx-Errors/s", src=partial(calc_rate, key="tx_errors")),
        ]
        self.table = TopTable(col_descs, "name")

    def get_name(self, entry, old_entry, elapsed_us):
        if entry["driver_name"] == "vcmp" or entry["driver_name"] == "ipsec":
            return entry["mgmt_type"] + "/" + entry["descr"]
        else:
            return entry["mgmt_type"] + "/" + entry["name"]

    def preprocess_ifaces(self, orig_ifaces):
        total = {
            "name": "total",
            "rx_bytes": 0,
            "rx_packets": 0,
            "rx_dropped": 0,
            "rx_errors": 0,
            "tx_bytes": 0,
            "tx_packets": 0,
            "tx_dropped": 0,
            "tx_errors": 0,
            "driver_name": "device",
            "mgmt_type": "DEVICE",
        }

        ifaces = []
        for i in orig_ifaces:
            if i["oper_state"] == "UP":
                ifaces.append(i)

            if i["driver_name"] in ["dpdk", "socket"]:
                total["rx_bytes"] += i["rx_bytes"]
                total["rx_packets"] += i["rx_packets"]
                total["rx_dropped"] += i["rx_dropped"]
                total["rx_errors"] += i["rx_errors"]
                total["tx_bytes"] += i["tx_bytes"]
                total["tx_packets"] += i["tx_packets"]
                total["tx_dropped"] += i["tx_dropped"]
                total["tx_errors"] += i["tx_errors"]

        ifaces.append(total)
        return ifaces

    def __call__(self, parser, namespace, values, option_string=None):
        sort_key = self.table.get_key_from_heading(values)
        sort_key = "rx_pps" if sort_key is None else sort_key
        limit = get_entry_limit(namespace)
        limit = 25 if limit == 0 else limit

        try:
            old_ifaces = {}
            old_timestamp_us = 0
            params = { "debug" : "iface_dump" }
            first = True
            while True:
                reply = remote_server.ifaceDump(**params)
                ifaces = reply["ifaces"]
                timestamp_us = reply["timestamp_us"]

                ifaces = self.preprocess_ifaces(ifaces)
                elapsed_us = timestamp_us - old_timestamp_us
                self.table.update_entries(ifaces, old_ifaces, elapsed_us)
                if not first:
                    self.table.print_table(ifaces, sort_key, limit)
                    print("")

                old_ifaces = { x[self.table.key] : x for x in ifaces }
                old_timestamp_us = timestamp_us
                time.sleep(1 if first else 2)
                first = False
        except KeyboardInterrupt:
            pass

class flowTopAction(argparse.Action):
    def __init__(self, **kwargs):
        super(flowTopAction, self).__init__(**kwargs)

        Col = TopTable.Col
        col_descs = [
            Col("logical_id", "Logical-ID"),
            Col("segment_id", "Segment-ID"),
            Col("src_ip", "Src-IP"),
            Col("dst_ip", "Dst-IP"),
            Col("src_port", "Src-Port"),
            Col("dst_port", "Dst-Port"),
            Col("protocol", "Protocol"),
            Col("ip_tos", "IP-ToS"),
            Col("rx_pps", "Rx-PPS", src=partial(self.calc_rate, key="pkts_rcvd")),
            Col("rx_kbps", "Rx-Kbps", src=partial(self.calc_rate, key="bytes_rcvd", div=125)),
            Col("tx_pps", "Tx-PPS", src=partial(self.calc_rate, key="pkts_sent")),
            Col("tx_kbps", "Tx-Kbps", src=partial(self.calc_rate, key="bytes_sent", div=125)),
        ]
        self.table = TopTable(col_descs, "logical_id")

    def calc_rate(self, entry, old_entry, elapsed_us, key, div=1):
        return entry[key] * 1000000 // elapsed_us // div

    def __call__(self, parser, namespace, values, option_string=None):
        sort_col = None
        params = { "delay_secs": 1 }
        for val in values:
            k, _, v = val.rpartition("=")
            if not k:
                sort_col = val
            else:
                params[k] = int(v)

        reply = remote_server.flowTop(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        sort_key = self.table.get_key_from_heading(sort_col)
        sort_key = "rx_pps" if sort_key is None else sort_key
        limit = get_entry_limit(namespace)
        limit = 25 if limit == 0 else limit

        self.table.update_entries(reply["flows"], {}, reply["elapsed_us"])
        self.table.print_table(reply["flows"], sort_key, limit)

        if reply["overflow_count"] != 0:
            print("Overflow count is %d" % reply["overflow_count"])

class flowHashTableStats(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "flowHashTableStats" }
        reply = remote_server.flowHashTableStats(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class natHashTableStats(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "natHashTableStats" }
        reply = remote_server.natHashTableStats(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class natPortHashTableStats(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "natPortHashTableStats" }
        reply = remote_server.natPortHashTableStats(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class flowFdispDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "flowFdispDump", "flowId": int(values[0])}
        reply = remote_server.fcFlowDispDebugDump(**params)

        if "error" in reply:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        print_fdisp_flows(reply, namespace);

class toggleShrAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if len(values) < 1:
                print(json.dumps({"result":"not enough arguments"}))

            arg_val = int(values[0])
            if arg_val != 0 and arg_val != 1:
                print(json.dumps({"result":"first argument needs to be 0/1"}))
                return

            params = {"enabled": arg_val}
            for i in range(1,len(values)):
                if 'stats_interval_ms' in values[i]:
                    arg_val = values[i].split('=')[1]
                    params.update({'stats_interval_ms': int(arg_val)})

            reply = remote_server.toggleShr(**params)
            print(json.dumps(reply, sort_keys = True, indent = 2))
        else:
            print(json.dumps({"result":"no input given"}))

class moduleVersionDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug" : "modules"}
        reply = remote_server.moduleVersionDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        module_version = []
        module_version.append(["module", "version", "lastUpdate", "updateCount"])
        for entry in reply:
            module_version.append([entry["module"],
                                entry["version"],
                                entry["lastUpdate"],
                                entry["updateCount"]])

        pretty_print_table(module_version)

class DHCP6PDDump(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        params = {"debug": "dhcp6_pd_dump"}
        reply = remote_server.dhcp6PDDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        pd_list = []
        pd_list.append(["Tag", "WAN interface", "Delegated Prefixes", "LAN interfaces",
                        "LAN IPv6 Address", "Prefixes Advertised"])

        for entry in reply:
            is_wan = True
            if len(entry["lanInterfaces"]) == 0:
                table_entry = []
                table_entry.append(entry["tagName"])
                table_entry.append(entry["wanInterface"]["name"])
                if len(entry["wanInterface"]["delegatedPrefixes"]):
                    table_entry.append(entry["wanInterface"]["delegatedPrefixes"][0]["prefix"]
                        + "/" + str(entry["wanInterface"]["delegatedPrefixes"][0]["prefixLen"]))
                else :
                    table_entry.append("")
                table_entry.append("")
                table_entry.append("")
                table_entry.append("")

                pd_list.append(table_entry)

            for lan in entry["lanInterfaces"]:
                table_entry = []
                if is_wan:
                    is_wan = False
                    table_entry.append(entry["tagName"])
                    table_entry.append(entry["wanInterface"]["name"])
                    if len(entry["wanInterface"]["delegatedPrefixes"]):
                        table_entry.append(entry["wanInterface"]["delegatedPrefixes"][0]["prefix"]
                          + "/" + str(entry["wanInterface"]["delegatedPrefixes"][0]["prefixLen"]))
                    else :
                        table_entry.append("")
                    table_entry.append(lan["name"])
                    table_entry.append(lan["address"])
                    if len(lan["prefixesAdvertised"]):
                        table_entry.append(lan["prefixesAdvertised"][0]["prefix"] + "/" +
                                           str(lan["prefixesAdvertised"][0]["prefixLen"]))
                    else :
                        table_entry.append("")
                else:
                    table_entry.append("")
                    table_entry.append("")
                    table_entry.append("")
                    table_entry.append(lan["name"])
                    table_entry.append(lan["address"])

                    if len(lan["prefixesAdvertised"]):
                        table_entry.append(lan["prefixesAdvertised"][0]["prefix"] + "/" +
                                           str(lan["prefixesAdvertised"][0]["prefixLen"]))
                    else :
                        table_entry.append("")
                pd_list.append(table_entry)

        pretty_print_table(pd_list)

class ATPProfiling(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        params = {"debug": "enable_diable_atp_profiling", "enable": int(value[0])}
        reply = remote_server.ATPProfiling(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        print(reply["result"])

class ATPProfilingDump(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        params = {"debug": "atp_profiling_dump"}
        reply = remote_server.dumpATPProfiling(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        print(reply["result"]["enable"])
        table = []
        table.append(["", "max_time", "min_time", "avg_time", "last_pkt", "num_of_packets"])
        table.append(["TCP", str(reply["result"]["TCP"]["max_time"]),
                     str(reply["result"]["TCP"]["min_time"]),
                     str(reply["result"]["TCP"]["avg_time"]),
                     str(reply["result"]["TCP"]["last_pkt"]),
                     str(reply["result"]["TCP"]["num_of_packets"])])

        table.append(["UDP", str(reply["result"]["UDP"]["max_time"]),
                     str(reply["result"]["UDP"]["min_time"]),
                     str(reply["result"]["UDP"]["avg_time"]),
                     str(reply["result"]["UDP"]["last_pkt"]),
                     str(reply["result"]["UDP"]["num_of_packets"])])

        table.append(["ICMP", str(reply["result"]["ICMP"]["max_time"]),
                     str(reply["result"]["ICMP"]["min_time"]),
                     str(reply["result"]["ICMP"]["avg_time"]),
                     str(reply["result"]["ICMP"]["last_pkt"]),
                     str(reply["result"]["ICMP"]["num_of_packets"])])

        table.append(["GRE", str(reply["result"]["GRE"]["max_time"]),
                     str(reply["result"]["GRE"]["min_time"]),
                     str(reply["result"]["GRE"]["avg_time"]),
                     str(reply["result"]["GRE"]["last_pkt"]),
                     str(reply["result"]["GRE"]["num_of_packets"])])

        table.append(["ESP", str(reply["result"]["ESP"]["max_time"]),
                     str(reply["result"]["ESP"]["min_time"]),
                     str(reply["result"]["ESP"]["avg_time"]),
                     str(reply["result"]["ESP"]["last_pkt"]),
                     str(reply["result"]["ESP"]["num_of_packets"])])

        table.append(["OTHERS", str(reply["result"]["OTHERS"]["max_time"]),
                     str(reply["result"]["OTHERS"]["min_time"]),
                     str(reply["result"]["OTHERS"]["avg_time"]),
                     str(reply["result"]["OTHERS"]["last_pkt"]),
                     str(reply["result"]["OTHERS"]["num_of_packets"])])

        pretty_print_table(table)

class URLReputationRemDiag(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        params = {"url": str(value[0])}
        reply = remote_server.urlRepRemDiag(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        print("URL: " + str(value[0]))
        print("Lookup Result: " + reply["status"])
        if "category" in reply.keys():
            print("Category: " + ', '.join(reply["category"]))
            print("Reputation: " + str(reply["rep_score"]))

class IPThreatDump(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        params = {"ip" : value[0]}
        reply = remote_server.wbIpThreatDump(**params)
        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return
        print("IP: " + str(value[0]))
        print("Lookup Result: " + reply["status"])
        if "threatType" in reply:
            print("Threat Type: " + ', '.join(reply["threatType"]))

class WebrootSdkStatus(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        params = {"debug" : "webroot_sdk_status"}
        reply = remote_server.webrootSdkStatus(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class efsUrlFcHashTableStats(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "efsUrlFcHashTableStats" }
        reply = remote_server.efsUrlFcHashTableStats(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class WebrootSetLogLevel(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) <  1:
            print("Insufficient Arguments")
            return
        if (not values[0].isdigit() or int(values[0]) not in [1,2,3,4,5]):
            print("First argument has to be digit and should be within 1-5 range")
            return

        if ((len(values) == 2) and
                values[1] not in ["edge_only","bcti_only","both"]):
            print("Second argument should one edge_only or bcti_only or both")
            return

        if (len(values) == 1):
            #Only log level passed so assume edge only
            log_location = "edge_only"
        else:
            log_location = values[1]

        params = {"loglevel":int(values[0]), "log_location":log_location}

        reply = remote_server.webrootsetloglevel(**params)
        if reply["result"] == "Sucess":
            log_output = []
            log_hdr = "*"*40
            print(log_hdr)
            print("Log Level     : ", reply["loglevel"])
            print("Log Location  : ", reply["log_location"])
            if "Note" in reply:
                print("Note          : ", reply["Note"])
        else:
            print(json.dumps(reply, sort_keys = True, indent = 2))

class ContextLogAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 0:
            params = {"tid": "all"}
            reply = remote_server.context_info_dump(**params)
            cmd = 'pidof edged'
            edged_pid = str(subprocess.check_output(shlex.split(cmd),
                                    universal_newlines=True)).strip()
            entries = []
            entries_js = []
            entries.append(["Thread Name", "Thread ID", "ON"])
            new_tid = ""
            for entry in reply:
                tid = str(entry["Thread ID"]).strip()
                if new_tid == tid:
                    continue;
                new_tid = tid
                cmd = 'cat /proc/{}/task/{}/comm'.format(edged_pid, new_tid)
                tname = str(subprocess.check_output(shlex.split(cmd),
                                    universal_newlines=True)).strip()
                entries.append([tname, new_tid, str(entry["On"])])
                entries_js.append(
                    {"thread-name":tname,"thread-id":int(new_tid),"on":int(entry["On"])})
            if not namespace.verbose:
                pretty_print_table(entries)
            else:
                print(json.dumps({"ctx_info":entries_js}, sort_keys = True, indent = 2))
        elif len(values) == 2:
            tid = values[0]
            enable = int(values[1])
            params = {"tid": tid, "enable": enable}
            reply = remote_server.context_set(**params)
            print(json.dumps(reply, sort_keys = True, indent = 2))

class hostapdACLCheck(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"hostapd_acl_check", "interface": values[0], "mac": values[1]}
        reply = remote_server.hostapdACLCheck(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))
class hostapdACLDelete(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"hostapd_acl_delete", "interface": values[0], "mac": values[1]}
        reply = remote_server.hostapdACLDelete(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class haResetFailover(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "haResetFailover" }
        reply = remote_server.haResetFailover(**params)

class schedXstatsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values[0] == "enable":
            params = { "sched_xstats": 1 }
        else:
            params = { "sched_xstats": 0 }
        reply = remote_server.schHierXstatsSet(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class autoSimSwitchDumpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            params = {"debug":"auto_sim_switch"}
            reply = remote_server.autoSimSwitchDump(**params)
            if reply == None:
                return

            print("============== Auto SIM Switch ==============")
            enabled = reply["sim_switch_status"]
            status = "ENABLED" if enabled else "DISABLED"
            print("status                : " + status)
            if enabled:
                switch_interval = reply["sim_switch_interval"]
                print("switchover_interval   : " + str(switch_interval) + " sec")
                sim_switch_in_prog = reply["sim_switch_in_prog"]
                print("SIM switch in prog    : " + str(sim_switch_in_prog))

                filename = "/tmp/USB/sim_switch_stats"
                with open(filename, "r") as file:
                    for i in range(2):
                        line = next(file).strip()
                        print(line)
        except IOError:
            print("No auto SIM switchover happened")
        except:
            print("Can't get auto SIM switchover status")

class upgradeStatus(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "upgradeStatus" }
        reply = remote_server.upgradeStatus(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class edgeDestInfoDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"display_option": "none"}
        if values:
            if (len(values) > 0):
                params = {"display_option": values[0]}
        reply = remote_server.edgeDestInfoDump(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class uuidCacheFreeCntAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"uuid_cache_free_cnt"}
        reply = remote_server.uuid_cache_free_cnt(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class showEdgeWssConf(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "show_edge_wss_config"}
        if (values):
            params = {"segmentId" : values[0]}
        else:
            params = {"segmentId" : -1}
        reply = remote_server.showEdgeWssConf(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class configWssTest(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "config_wss_test"}
        if values:
            if (len(values) != 1):
                print("Incorrect Argument - give a json filename")
                return
            else:
                params = {"filename" : values[0]}
        else:
            print("Incorrect Argument - give a json filename")
            return
        reply = remote_server.configWssTest(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class configWssBizTest(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "config_wss_biz_test"}
        if values:
            if (len(values) != 1):
                print("Incorrect Argument - give a json filename")
                return
            else:
                params = {"filename" : values[0]}
        else:
            print("Incorrect Argument - give a json filename")
            return
        reply = remote_server.configWssBizTest(**params)
        print(json.dumps(reply, sort_keys = True, indent = 2))

class clientConnector(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = { "debug": "client_connector" }
        if len(values) == 0:
            print("Need atleast 1 argument.")
            print("Usage: debug.py --client_connector dump [info, ip, status, version]")
            print("       debug.py --client_connector restart")
            print("       debug.py --client_connector status")
            print("       debug.py --client_connector set_max_cpu_percent <percent_value>")
            return
        if values[0] == "status":
            status = cc_common.get_client_connector_status()
            reply = remote_server.clientConnectorDump(**params)
            if (reply.get("enabled")):
                reply.update(status)
            print(json.dumps(reply, sort_keys = True, indent = 2))
        elif values[0] == "dump":
            cc_common.client_connector_dump(values)
        elif values[0] == "restart":
            cc_common.client_connector_restart()
        elif values[0] == "set_max_cpu_percent":
            max_cpu_percent = os.cpu_count() * 25
            if len(values) > 1 and values[1].isdigit():
                val = int(values[1])
                if val > 0 and val <= max_cpu_percent:
                    cc_common.client_connector_set_cpu_max(val)
                else:
                    print("Invalid Cpu Percentage. Valid range <1 - {0}>".format(max_cpu_percent))
            else:
                print("Cpu Percentage must be a number value. "
                      "Valid range <1 - {0}>".format(max_cpu_percent))

class showLacpInfo(argparse.Action):
    ifaces_dict = {}
    lacp_state_map = [{"flag":0x1, "str":"ACTIVITY"},
                      {"flag":0x2, "str":"TIMEOUT"},
                      {"flag":0x4, "str":"AGGREGATION"},
                      {"flag":0x8, "str":"SYNCHRONIZATION"},
                      {"flag":0x10, "str":"COLLECTING"},
                      {"flag":0x20, "str":"DISTRIBUTING"},
                      {"flag":0x40, "str":"DEFAULTED"},
                      {"flag":0x80, "str":"EXPIRED"}]
    def fetch_ifaces(self):
        try:
            self.ifaces_dict = {v:k for k, v in hardwareinfo.ALL_WIRED_LINKS.items()}

        except Exception as e:
            self.ifaces_dict = {}

    def get_lacp_port_state_str(self, value):
        ret = ""
        first = 1
        for i, entry in enumerate(self.lacp_state_map):
            if value & entry["flag"]:
                if first:
                    ret += entry["str"]
                    first = 0
                else:
                    ret += " " + entry["str"]
        return ret

    def parse_fill_lacp_info_per_iface(self, iface_name):
        lines = None
        file_name = LACP_BOND_DIR + iface_name
        iface_logical_name = iface_name.split(LACP_BOND_PREFIX, 1)[1]
        try:
            with open(file_name, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            return {"error" : "Invalid interface {}".format(iface_logical_name)}

        if lines is None:
            return {}

        ret = {}
        iface_logical_name = iface_name.split(LACP_BOND_PREFIX, 1)[1]
        ret["interface_name"] = iface_logical_name
        ret["active_aggregator_info"] = {}
        cur_slave = None
        current_section = None
        active_aggregator_info = {}

        key_value_pattern = re.compile(r"^(.*?):\s+(.*)$")
        slave_pattern = re.compile(r"^Slave Interface:\s+(.*)$")
        actor_section_pattern = re.compile(r"^details actor lacp pdu:$")
        partner_section_pattern = re.compile(r"^details partner lacp pdu:$")
        active_agg_info_pattern = re.compile(r"^Active Aggregator Info:$")
        first_slave = 1
        for line in lines:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            if active_agg_info_pattern.match(line):
                current_section = "active_aggregator_info"
                active_aggregator_info = {}
                #place holder for what we will parse in this section
                ret["active_aggregator_info"] = active_aggregator_info
                continue

            slave_match = slave_pattern.match(line)
            if slave_match:
                if first_slave:
                    first_slave = 0
                    ret["slave_interfaces"] = []
                cur_slave = {
                    "interface_name":""
                }
                physical_name = slave_match.group(1)
                logical_name = self.ifaces_dict[physical_name] if physical_name in \
                               self.ifaces_dict else physical_name
                cur_slave["interface_name"] = logical_name
                ret["slave_interfaces"].append(cur_slave)
                #we have seen a new slave, soon we will see actor and partner sections
                current_section = None
                continue

            # Check for actor or partner sections
            if actor_section_pattern.match(line):
                current_section = "actor"
                cur_slave["actor"] = {}
                continue
            if partner_section_pattern.match(line):
                current_section = "partner"
                cur_slave["partner"] = {}
                continue

            # Parse key-value pairs
            kv_match = key_value_pattern.match(line)
            if kv_match:
                key, value = kv_match.groups()
                key = key.lower().replace(" ", "_")
                key = re.sub(r"[()]", "", key)
                value = value.strip()
                value = int(value) if value.isdigit() else value
                if key == "port_state":
                    value = self.get_lacp_port_state_str(value)
                # Store data in appropriate section
                if current_section == "active_aggregator_info":
                    active_aggregator_info[key] = value
                elif current_section and cur_slave is not None:
                    cur_slave[current_section][key] = value
                elif cur_slave is not None:
                    cur_slave[key] = value
                else:
                    ret[key] = value
        return ret
    def get_lacp_info_json(self, if_name="all"):
        self.fetch_ifaces()
        iface_names = []
        if if_name == "all":
            iface_names = [f for f in os.listdir(LACP_BOND_DIR) if \
                          os.path.isfile(os.path.join(LACP_BOND_DIR, f))]
        else:
            iface_names.append(LACP_BOND_PREFIX + if_name)

        ret = []
        for iface in iface_names:
            ret.append(self.parse_fill_lacp_info_per_iface(iface))
        return ret

    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) > 1):
                print("Incorrect Argument - Enter a parent bond iface name")
                return
            elif len(values) == 0:
                if_name = "all"
            else:
                if_name = values[0]
        else:
            if_name = "all"
        params = {"if_name" : if_name, "status_only" : 1}
        reply = self.get_lacp_info_json(if_name)
        reply_stats = remote_server.lacpStatsDump(**params)

        if len(reply) == 0 or "error" in reply[0]:
            print(reply)
            return

        bond_status = {}
        for bond in reply_stats:
            bond_status[bond["bond_name"]] = bond["oper_status"]

        for bond_idx, bond in enumerate(reply):
            reply[bond_idx]["oper_status"] = bond_status.get(bond["interface_name"], "UNKNOWN")

        if namespace.verbose:
            print(json.dumps(reply, indent=2))
            return

        output = []
        output.append(["LAG Interface", "LAG Status", "Slave Port",
                       "Actor Status", "Partner Status"])
        for bond_idx, bond in enumerate(reply):
            bond_entry = None
            if bond["slave_interfaces"] is None or len(bond["slave_interfaces"]) == 0:
                output.append([bond["interface_name"],
                              bond_status.get(bond["interface_name"], "UNKNOWN"),
                              "-","-", "-"])
                continue
            for idx, slave in enumerate(bond["slave_interfaces"]):
                parent = " "
                parent_status = " "
                if idx == 0:
                    parent = bond["interface_name"]
                    parent_status = bond_status.get(bond["interface_name"], "UNKNOWN")
                mii_status = slave["mii_status"] == "up"
                actor_state = slave["actor"]["port_state"]
                partner_state = slave["partner"]["port_state"]

                actor_state_str = "UP" if ("DISTRIBUTING" in actor_state and \
                                "COLLECTING" in actor_state and mii_status) else "DOWN"
                partner_state_str = "UP" if ("DISTRIBUTING" in partner_state and \
                                "COLLECTING" in partner_state and mii_status) else "DOWN"
                bond_entry = [parent, parent_status, slave["interface_name"],
                                  actor_state_str, partner_state_str]
                output.append(bond_entry)

        pretty_print_table(output)


class showLacpStats(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) > 1):
                print("Incorrect Argument - Enter a parent bond iface name")
                return
            elif len(values) == 0:
                if_name = "all"
            else:
                if_name = values[0]
        else:
            if_name = "all"
        params = {"if_name" : if_name, "status_only":0}
        reply = remote_server.lacpStatsDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        #if making a change here, also remember to change LACP_STATS output in remote diag
        output.append(["LAG Interface", "Slave Interface", "LACP PDU Tx Packets",
                     "LACP PDU Tx Bytes", "LACP PDU Rx Packets", "LACP PDU Rx Bytes"])
        for bond in reply:
            if bond["slaves"] is None or len(bond["slaves"]) == 0:
                output.append([bond["bond_name"], "-", "0", "0", "0", "0"])
                continue
            for idx, slave in enumerate(bond["slaves"]):
                parent = " "
                if idx == 0:
                    parent = bond["bond_name"]
                output.append([parent, slave["slave_name"], str(slave["tx_lacp_packets"]),
                              str(slave["tx_lacp_bytes"]), str(slave["rx_lacp_packets"]),
                              str(slave["rx_lacp_bytes"])])
        pretty_print_table(output)

class showLacpSlaves(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            if (len(values) > 1):
                print("Incorrect Argument - Enter a parent bond iface name")
                return
            elif len(values) == 0:
                if_name = "all"
            else:
                if_name = values[0]
        else:
            if_name = "all"
        params = {"if_name" : if_name}
        reply = remote_server.lacpSlavesDump(**params)

        if namespace.verbose:
            print(json.dumps(reply, sort_keys = True, indent = 2))
            return

        output = []
        output.append(["LAG-Interface", "Active-Slaves"])
        for bond in reply:
            if bond["slaves"] is None or len(bond["slaves"]) == 0:
                output.append([bond["bond_name"], "-"])
                continue
            for idx, slave in enumerate(bond["slaves"]):
                parent = " "
                if idx == 0:
                    parent = bond["bond_name"]
                output.append([parent, slave["slave_name"]])
        pretty_print_table(output)

class limitCtrlTrafficDebugDump(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        params = {"debug":"limit_ctrl_traffic"}
        reply = {}
        if len(values):
           for i in range (len(values)):
                if 'clock_sync_interval_min' in values[i]:
                    arg_val = values[i].split('=')[1]
                    if arg_val.isdigit():
                       params.update({'clock_sync_interval_min': int(arg_val)})
                    else:
                       print("Clock sync interval must be a number value. ")
                elif 'disable_hb_probe' in values[i]:
                    arg_val = values[i].split('=')[1]
                    if arg_val.isdigit():
                       params.update({'disable_hb_probe': int(arg_val)})
                    else:
                       print("HB probe must be a binary value. ")
                elif 'traffic_hb_ms' in values[i]:
                    arg_val = values[i].split('=')[1]
                    if arg_val.isdigit():
                       params.update({'traffic_hb_ms': int(arg_val)})
                    else:
                       print("HB interval must be a number value. ")
           reply = remote_server.limitCtrlTrafficDebugDump(**params)
        else:
           reply = remote_server.limitCtrlTrafficDebugDump(**params)

        print(json.dumps(reply, sort_keys = True, indent = 2))

sysparser = argparse.ArgumentParser(description='system settings', add_help=False)
sysparser.add_argument('--timeout', action=setTimeoutAction, nargs=1, metavar='TIMEOUT (SECONDS)', default=2, help='Override the default timeout of 2 seconds')
sysparser.add_argument('--logfile', action=setLogfileAction, nargs=1, metavar='LOGFILE',
                       default="NIL", help='filename to store the debug logs')

parser = argparse.ArgumentParser(formatter_class=HelpSorterClass, description='Debug dump from edged')
parser.add_argument('--mode_link', action=linkModeDebugDump, nargs=0, help='Display Backup/Hotstandby info')
parser.add_argument('--timeout', action='store', nargs=1, metavar='TIMEOUT (SECONDS)', default=["2"], help='Override the default timeout of 2 seconds')
parser.add_argument('--logfile', action='store', nargs=1, metavar='LOGFILE', default="NIL",
                     help='filename to store the debug logs')
parser.add_argument('--limit', action='store', nargs=1, metavar='N', default=["0"], help='Limit the number of entries displayed')
parser.add_argument('-v', '--verbose', action='store_true', help='Output raw JSON instead of formatted display')
parser.add_argument('--biz_pol_dump', action=BizPolDumpAction, nargs='*', default=['all', 'all'], metavar=('[all | segment-id]', '[all | policy-name]'), help='dump the current business policies')
parser.add_argument('--netflow_intervals', action=NetFlowIntervals, nargs=0, help='Display Netflow Intervals only in verbose namespace')
parser.add_argument('--netflow_collectors', action=NetFlowCollectors, nargs=0, help='Dump NetFlow Collectors')
parser.add_argument('--netflow_filters', action=NetFlowFilters, nargs=1, metavar=('[<collector_id>]'), help='Dump Netflow Filters of a Collector')
parser.add_argument('--bw_testing_dump', action=bwTestDumpAction, nargs=0, help='dump the current bw test data')
parser.add_argument('--chat_stats', action=chatStatsAction, nargs='*', default=None,
                    metavar=('[sip=] [dip=] [dport=] [app_id=] [pretty_file_name=]'),
                    help='dump the current conversation stats')
parser.add_argument('--app_chat_stats', action=appChatStatsAction, nargs=1, metavar=('[<app-id>]'), help='dump the current app conversation stats')
parser.add_argument('--clock_sync', action=clockSyncAction, nargs=0, help='dump the current clock sync state')
parser.add_argument('--timer', action=timerSyncAction, nargs=0,
                    help='dump the current timer wheel state')
parser.add_argument('--cos', action=linkCosAction, nargs=0, help='dump link classes of Service')
parser.add_argument('--current_apps', action=currentAppsDumpAction, nargs=0, help='dump current identified applications')
parser.add_argument('--gateways', action=gatewayDumpAction, nargs=0, help='dump the current list of VeloCloud gateways')
#TODO: Fix the logical naming of USB ports
parser.add_argument('--debug_bw_test', action=bwTestAction, nargs=1, choices=WAN_LINKS,
                    help='Run a bandwidth test on the path(s) connected through an interface')
parser.add_argument('--bw_test_link', action=linkBwTestAction, nargs=1, metavar='logical-id', help="Retest the bandwidth on a link by internal logical ID")
parser.add_argument('--bw_retest', action=bwRetestAction, nargs=0, help='retest the bw on all interfaces')
parser.add_argument('--dec', action=decAction, nargs=0, help='dump the current dynamic error correction status')
parser.add_argument('--qoe_threshold', action=qoeThresholdAction, nargs=0,
                    help='dump the current QoE threshold values')
parser.add_argument('--diag_trigger', action=diagTriggerAction, nargs=0, help='trigger diag')
parser.add_argument('--dns_name_cache', action=dnsNameCacheDumpAction, nargs="*",
                    help='dump the dns domain name cache',
                    metavar=('[v4 | v6 | all]'))
parser.add_argument('--dns_name_lookup', action=dnsNameCacheLookupAction, nargs='*',
                    metavar=('[HOSTNAME] [ v4 | v6 | all]'),
                    help='lookup a hostname in the dns domain name cache')
parser.add_argument('--dns_ip_cache', action=dnsIpCacheDumpAction, nargs="*",
                    help='dump the dns ip cache', metavar=('[v4 | v6 | all]'))
parser.add_argument('--dns_ip_cache_lru', action=dnsIpCacheLRUDumpAction, nargs="*",
                    help='dump the dns ip cache LRU', metavar=('[v4 | v6 | all]'))
parser.add_argument('--dns_ip_lookup', action=dnsIpCacheLookupAction, nargs=1,
                    metavar='IP ADDRESS', help='lookup an address in the dns ip cache')
parser.add_argument('--dns_ip_cache_flush', action=dnsIpCacheFlushAction, nargs='*',
                    metavar=('[IP ADDRESS | v4 | v6 | all]'), help='flush the dns ip cache')
parser.add_argument('--dns_ip_cache_update_ttl', action=dnsIpCacheUpdateTtlAction, nargs=2,
                    metavar=('[IP ADDRESS]', '[TTL]'), help='update dns ip cache ttl')
parser.add_argument('--firewall_dump', action=FirewallDumpAction,  nargs='*', default="all all",
                    metavar=('[all | segment-id]', '[v4 | v6 | all]'),
                    help='dump the current firewall version and policies')
parser.add_argument('--uflow_dump', action=UflowDumpAction, nargs=3, metavar=('[all | src-ip]', '[all | dest-ip]', '[all|segid]'), help='dump the current uflow table entries')
parser.add_argument('--qat_dump', action=qatDump, nargs=0, help='dump the qat info')
parser.add_argument('--flow_dump', action=FlowDumpAction, nargs='*',
                    default = ['all', 'all', 'all', 'all'],
                    metavar=('[local | logical-id | all] [all | dstip ] [segid | all]',
                             '[all | v4 | v6]'),
                    help='dump the current flow table entries')
parser.add_argument('--flow_route_dump', action=FlowDumpAction, nargs='*',
                     default = ['all', 'all', 'all', 'all'],
                     metavar=('[local | logical-id | all] [all | dstip] [segid | all]',
                              '[flowIdx | noroute]'),
                     help='dump the current flow_route table entries')
parser.add_argument('--flow_flush', action=FlowFlushAction, nargs='?', metavar=('flow-id'), help='flush the current flow table entries')
parser.add_argument('--flow_set_idps_state', action=FlowSetIdpsState, nargs=2,
                    metavar=('[flow-id]','[allow | block]'),
                    help='Set flow idps state to [allow | block]')
parser.add_argument('--flow_set_timeout', action=FlowSetTimeout, nargs=2, metavar=('[protocol]', '[Timeout in seconds]'), help='Set idle timeout value for flows')
parser.add_argument('--flow_trace', action=flowTraceAction, nargs = '*',
                    metavar=('[v4|v6]|segment_id=<int>|protocol=<int>|'
                             'src_port=<int>|dst_port=<int>|src_ip=<str>|dst_ip=<str>|'
                             'count=<int>|timeout=<int>'),
                    help='Trace user-flows')
parser.add_argument('--nat_db_flush', action=natDbFlushAction, nargs="*",
                    help='flush the NAT database entries',
                    metavar=('[v4 | v6 | all]'))
parser.add_argument('--nat_delete', action=natDeleteAction, nargs=7, metavar=('<seg_id>','<src_ip>', '<src_port>', '<dst_ip>', '<dst_port>', '<proto>', '<nat_type>'),
                    help='delete the NAT entry using the provided original five tuple and nat type')
parser.add_argument('--jitter', action=JitterDumpAction, nargs=0, help='dump the current jitter buffer enabled flow table entries')
parser.add_argument('--link_stats', action=linkStatsAction, nargs='*', default=['all','up'],
                    metavar=('[v4 | v6 | all]','[up | all]'), help='dump the current link stats')
parser.add_argument('--path_stats', action=pathStatsAction, nargs='*', default="all",
                    metavar=('[v4 | v6 | all]'),help='dump the current path stats')
parser.add_argument('--psummary', action=pathStatsSummaryAction, nargs=0, help='dump the current path summary')
parser.add_argument('--sub_path_stats', action=subPathStatsAction, nargs='?', default ="all", metavar=('[all | peer-id]'),help='dump the current sub path stats')
parser.add_argument('--tunnel_counts', action=tunnelCountsAction, nargs=1, metavar=('[logical-id | all]'), help='dump the tunnel count of connected edges')
parser.add_argument('--qos_override', action=qosOverrideAction, nargs=1, choices=['gateway', 'direct', 'off', 'current'], help='override the QoS policies globally')
parser.add_argument('--rx_bw_cap_kbps', action=rxBwCapAction, nargs=2, metavar=('INTERFACE', 'KBPS'),
                    help='Cap the downstream bandwidth on a link explicitly')
parser.add_argument('--pr_rr_reg' , action=dbgPrRegRefresh, nargs=2, metavar=('gw_logicalid', 'peer_id'),
                    help='Register route refresh for a remote peer')
parser.add_argument('--verbose_firewall_dump', action=verboseFirewallDumpAction,  nargs='*',
                    default="all all", metavar=('[all | segment-id]', '[v4 | v6 | all]'),
                    help='verbose dump the current firewall version and policies')
parser.add_argument('--verbose_biz_pol_dump', action=verboseBizPolDumpAction, nargs='*', default=['all','all'], metavar=('[all | segment-id]', '[all | policy-name]'), help='verbose dump the current business policies')
parser.add_argument('--wireless_signal_strenth_update', action=wirelessSignalStrengthAction, nargs=1, choices=['USB1', 'USB2', 'USB3', 'USB4'],
                    help='Update and dump the wirelss link signal strength')
parser.add_argument('--routes', action=unifiedRouteDebugDump,
                    default='all all all',
                    nargs='*',
                    metavar=('[all|prefix] [all|segment-id] [all|v4|v6]'),
                    help='dump the unified vc route table')
parser.add_argument('--unique_routes', action=uniqueRouteDebugDump,
                    default='all all all', nargs='*',
                    metavar=('[all|prefix] [all|segment-id] [all|v4|v6]'),
                    help='dump the unique vc route table')
parser.add_argument('--peer_routes', action=PeerRouteDebugDump,
                    default='all',
                    nargs= '*', metavar=('[all|v4|v6]'),
                    help='dump the peer route table')
parser.add_argument('--local_routes', action=localRouteDebugDump,
                    default='all all all', nargs='*',
                    metavar=('[all|prefix] [all|segment-id] [all|v4|v6]'),
                    help='dump the local vc route table')
parser.add_argument('--control_bytes', action=controlbytes, nargs = '*', metavar=('clear | all', 'peer | link'), help = 'dump the number of bytes and packets/messages of tx and rx control messages on each link/peer ')
parser.add_argument('--connected_routes', action=connectedRouteDebugDump,
                    default='all all all', nargs='*',
                    metavar=('[all|prefix] [all|segment-id] [all|v4|v6]'),
                    help='dump the connected vc route table')
parser.add_argument('--overlay_routes', action=overlayRouteDebugDump,
                    default='all all all', nargs='*',
                    metavar=('[all|prefix] [all|segment-id] [all|v4|v6]'),
                    help='dump the overlay vc route table')
parser.add_argument('--remote_routes', action=remoteRouteDebugDump, nargs='*',
                    default="all all all all",
                    metavar=('[all|prefix] [all|segment-id] [all|v4|v6] [all|dest-logical-id]'),
                    help='dump the remote vc route table')
parser.add_argument('--dc_routes', action=datacenterRouteDebugDump,
                    default='all all', nargs='*',
                    metavar=('[all|prefix] [all|segment-id]'),
                    help='dump the datacenter route table')
parser.add_argument('--verbose_routes', action=verboseRouteDebugDump,
                    default='all all all', nargs='*',
                    metavar=('[all|prefix] [all|segment-id] [v4|v6|all]'),
                    help='dump the unified vc route table without formatting')
parser.add_argument('--dce_edge', action=dceEdgesDebugDumpAction, nargs='*', default='all',
                    metavar=('[v4 | v6 | all]'), help='dump the list of DCE edges pushed from VCG')
parser.add_argument('--hub_list', action=hubListDump, nargs='?', default="all", help='dump the list of hubs configured')
parser.add_argument('--rsummary', action=edgeRouteSummary, default ="all", nargs='*', help='routes summary.Options can be [all | seg_id]')
parser.add_argument('--user_route_dump', action=userRouteDumpAction,
        default="all all all all",
        nargs='*',
        metavar=('[all|segment] [all|v4|v6] [all|prefix] [all|preferred]'),
        help='Usage: debug.py --user_route_dump [all|segment] [all|v4|v6] [all|prefix] '
        '[all|preferred]. If preferred is specified for the fourth param, only the best reachable '
        ' route is dumped. If there are no reachable routes, first unreachable route is dumped. '
        'If all is speficied for the fourth param all routes are dumped. Used in '
        'remote diag route dump.')
parser.add_argument('--local_subnets', action=localSubnetDumpAction, nargs=0, help='dump the current local subnets')
parser.add_argument('--ike', action=ikeDumpAction, nargs='*',
                    help='Usage: --ike [all | v4 | v6]; Dump the current IKE descriptors')
parser.add_argument('--ike_resource', action=ikeResAction, nargs=0,
                    help='Dump the current IKE resource stats')
parser.add_argument('--ike_down', action=ikeDownAction, nargs=1, metavar=('cookie'),
                    help='For debugging only - set the IKE descriptors by cookie in hex to DOWN' \
                        ' state and restart')
parser.add_argument('--ike_delete_p1_sa', action=ikeDeleteP1SaAction, nargs=2,
        metavar=('[peer_ip]', '[cookie]'),
        help='For debugging only - manually delete a P1 SA entry by cookie in hex')
parser.add_argument('--ike_delete_tunnel', action=ikeDeleteTunnel, nargs=1, metavar=('cookie'),
                    help='Delete IKE tunnel by cookie in hex')
parser.add_argument('--ike_childsa', action=ikeChildsaDumpAction, nargs='*', help='Usage: --ike_childsa [all | v4 | v6 [all | peer_ip [all | ikeSaSpi [count]]]]; Dump the current Child SAs')
parser.add_argument('--ike_stalesa', action=ikeStalesaDumpAction, nargs='*',
                    help='Dump the stale Child SAs (if any)')
parser.add_argument('--ike_sa', action=ikeSaDumpAction, nargs='*',
                    help='Usage: --ike_sa [all | v4 | v6 [all | peer_ip [count]]]; ' \
                            'Dump the current IKE SAs')
parser.add_argument('--ike_spd', action=ikeSpdDumpAction, nargs='*',
        help='Usage: --ike_spd [all | peer_ip]; Dump the current Security Policy (SP)')
parser.add_argument('--endpoints', action=endpointDumpAction, nargs='*', default="all",
                    metavar=('[v4 | v6 | all]'), help='dump the current vcmp endpoint table')
parser.add_argument('--static_routes', action=staticRouteDumpAction, nargs='*', default="all",
                    metavar = ('[v4 | v6 | all]'),
                    help='Usage:--static_r [all | v4 | v6 ]; dump the current static routes table')
parser.add_argument('--bwcap', action=linkBwCapDump, nargs=0, help='dump the link bandwidth caps')
parser.add_argument('--handoffqdbg', action=handoffqDbgDump, nargs='*',
                    help='<nothing>|<reset>: dump handoffq related info | reset the counters')
parser.add_argument('--admission_control', action=admissionControlAction, nargs='*',
        help='<nothing>|<enable [threshold N]>|<disable>: admission control status | enable '
        + 'admission control [set mbuf threshold percentage] | disable admission control')
parser.add_argument('--dpt_set_yield_config', action=dptYieldAction, nargs="*",
                    help='Set DP yield configuration '
                    '<adaptive|legacy|linear|log> <min_yield> <max_yield>')
parser.add_argument('--logger_setlevel', action=loggerOverrideDefaultsAction, nargs='+', help='override the default log level of modules. --logger_setlevel level_num [module=moduleName[,moduleName[,...]] [logX]]')
parser.add_argument('--ike_logger_setlevel',
                      action=ikeLoggerOverrideDefaultsAction, nargs='*',
                      help='Override the IKE module\'s default log level. Usage:'\
                            ' --ike_logger_setlevel global_level_num[3-10,99]'\
                            ' ikev1_level_num[3-10,99] enable_notice[0/1]'\
                            ' module_name=module_level_num,..[3-10,99]'\
                      '3: External, non-fatal, high-level errors. Ex: an incorrect format '\
                          'received from an outside source, or failed negotiation.\n'\
                      '4: Positive high-level information, such as a succeeded negotiation.\n'\
                      '5: Starting a high or middle-level operation. For example: '\
                          'the start of a negotiation, or opening a device.\n'\
                      '6: Uncommon situations that might be caused by a bug.\n'\
                      '7: Nice-to-know information, such as entering or exiting a function, or a '\
                          'result of a low-level operation.\n'\
                      '8: Data block dumps (hash, keys, certificates, or '\
                          'other non-massive data blocks).\n'\
                      '9: Protocol packet dumps.\n'\
                      '10: Mid-results (non-final results).\n'\
                      '99: Display most of the debugging information.'\
                           'This should be used with discretion as it is CPU intensive\n')
parser.add_argument('--logger_setsquelching', action=loggerSetSquelchState, nargs='+', help='Disable or Enable log squelching, and set maximum number of log entries to be squelched. --logger_setsquelching on|off [max=dddd]')
parser.add_argument('--logger_on_off', action=loggerCtxOnOff, nargs='+', help='Disable or Enable log using its context name | --logger_on_off name=<ctx name> enable=<on/off>')
parser.add_argument('--verbose_arp_dump', action=verboseArpDumpAction, nargs='*', help='--verbose_arp_dump [Number of entries]. Prints all entries if number of entries is not specified or give as 0. Dump the arp cache for active interfaces.')
parser.add_argument('--verbose_nd6_dump', action=verboseNd6DumpAction, nargs='*',
        help='--verbose_nd6_dump [Number of entries]. Dump the nd6 cache for active interfaces.')
parser.add_argument('--arp_dump', action=ArpDumpAction, nargs='*', help='--arp_dump [Number of entries]. Prints all entries if number of entries is not specifid or give as 0. Dump the arp cache for active interfaces.')
parser.add_argument('--nd6_dump', action=Nd6DumpAction, nargs='*',
                help='--nd6_dump [Number of entries]. Dump the nd6 cache for active interfaces.')
parser.add_argument('--clear_arp_cache', action=ClearArpCache, nargs=1, metavar ='IFNAME', help='Clear the arp cache')
parser.add_argument('--clear_nd6_cache', action=ClearND6Cache, nargs=1, metavar ='IFNAME',
                    help='Clear the nd6 cache')
parser.add_argument('--list_vpn_endpoints', action=vpnTestDumpAction, nargs=1, help='dump the list of endpoints available for VPN Testing')
parser.add_argument('--remote_services', action=remoteServicesDumpAction, nargs=0, help='dump the list of allowed remote services')
parser.add_argument('--update_mgd_route', action=updateMgdRouteAction, nargs=0, help='toggle whether MGD should be sent via GW or direct')
parser.add_argument('--ha', action=haDumpAction, nargs=1, metavar=('[verp | lstate | mgd_update |'
                    ' spath | apath | ftrack | tcp | los_state]'),
                    help='dump the HA verp state of the edge or the interface'
                         'mac/ip related information')
parser.add_argument('--ha_switch', action=haSwitchAction, nargs=0, help='Switch the HA state of the edge, if its ACTIVE')
parser.add_argument('--vrrp_dump', action=vrrpDumpAction, nargs=0, help='dump HA vrrp state of the edge')
parser.add_argument('--vrrp_load', action=vrrpLoadAction, nargs=0, help='load HA vrrp configure file')
parser.add_argument('--vrrp_shutdown', action=vrrpShutdownAction, nargs=0, help='stop HA vrrp of the edge')
parser.add_argument('--vrrp_startup', action=vrrpStartupAction, nargs=0, help='start HA vrrp of the edge')
parser.add_argument('--vrrp_enable', action=vrrpEnableAction, nargs=0, help='enable HA vrrp of the edge')
parser.add_argument('--vrrp_set_priority', action=vrrpSetPriorityAction, nargs=1, default=50, help='set HA vrrp priority to [priority]')
parser.add_argument('--vrrp_reset_priority', action=vrrpResetPriorityAction, nargs=0, help='reset HA vrrp priority to 50')
parser.add_argument('--nat_dump', action=natDumpAction, nargs='*',
    help='[orig | mod] [all | v4 | v6] [Filter list: '
         'type|proto|sip|sport|dip|dport|msip|mdip|msport|mdport|count]; '
         'Dump NAT info syncd from ACTIVE')
parser.add_argument('--stale_nat_dump', action=staleNatDumpAction, nargs=0,
                    help='Dump the list of stale nat entries')
parser.add_argument('--nat_port_dump', action=natPortDumpAction, nargs='*',
    help='Usage: [v4 | v6 | all] [Filter list: proto|sip|dip|dport]; '
         'dump the current NAT port table')
parser.add_argument('--nat_port_restricted_dump', action=natPortRestrictedDumpAction, nargs='*',
    help='Usage: [v4 | v6 | all] [Filter list: proto|inside_sip|'
         'inside_sport|outside_sip|outside_sport]; '
         'dump the current NAT port restricted table')
parser.add_argument('--nat_summary', action=natSummaryAction, nargs='*',
    help='Usage: [orig | mod] [v4 | v6 | all] '
         '[Filter list: type|peer_id|seg|proto|sip|sport|dip|dport|msip|mdip];'
         'Show summary counts for NAT table')
parser.add_argument('--pptp_conn_map_dump', action=pptpConnMapDumpAction, nargs=0,
    help='Dumps the table that maps PPTP control channel connection information to corresponding '
         'GRE callid values')
parser.add_argument('--debug_path_uptime', action=pathUptimeDumpAction, nargs=0,
                    help='dump the pathuptime hash table')
parser.add_argument('--ipid_dump', action=ipIdDumpAction, nargs='*',
                    help='Usage: [v4 | v6 | all]; dump the current IP ID table')
parser.add_argument('--ha_flow_dump', action=haFlowDumpAction, nargs='?', default="all", metavar=('[all | dest-ip]'), help='Dump flow info syncd from ACTIVE')
parser.add_argument('--applications', action=applicationDumpAction, nargs=0, help='dump the current list of applications')
parser.add_argument('--app_ip_port_db', action=appMapIP_PortDB, nargs=0, help='dump the current list of fast learned ip routable applications')
parser.add_argument('--app_ip_port_cache', action=ipPortCacheDump, nargs='*',
                    default='all', metavar=('[v4 | v6 | all]'),
                    help='dump the current list of fast learned ip routable applications')
parser.add_argument('--app_ip_port_cache_flush', action=ipPortCacheFlush, nargs=0,
                    help='Clear the slow learning cache')
parser.add_argument('--app_proto_port_db', action=appMapProtoPortDB, nargs=0, help='dump the current list of port routable applications')
parser.add_argument('--app_fqdn_db', action=appMapFQDNDB, nargs=0,
                    help='dump the current list of FQDN associated applications')
parser.add_argument('--qos_net', action=NetQoSDebug, nargs=3, metavar=('[ <peer_id> | gateway ]', '[ all | <segid> ]', '[ stats | clear_drops ]'), help='Net QoS Debug interface')
parser.add_argument('--qos_link', action=LinkQoSDebug, nargs=2, metavar=('[ <peer_id> | local ]', '[ stats | clear_drops ]'), help='Link QoS Debug interface')
parser.add_argument('--qos_link_pq', action=LinkQoSDebugPQ, nargs=1, metavar=('[ on | off | status ]'), help='Link QoS Priority queue config interface')
parser.add_argument('--qos_dump_net', action=NetQoSDump, nargs=0, help='Net QoS Dump')
parser.add_argument('--qos_dump_link', action=LinkQoSDump, nargs=0, help='Link QoS Dump')
parser.add_argument('--flow_stats', action=flowStats, nargs='?',
                    metavar=('<peer_id>'), help='Show flow stats')
parser.add_argument('--uptime', action=uptime, nargs=0, help='Dump process uptime')
parser.add_argument('--pki', action=pkiDumpAction, nargs=0, help='dump the current pki configuration')
parser.add_argument('--ospfd_dump', action=ospfDumpAction, nargs='*',
        metavar=('[v4 | v6 | all], [seg | all]'),
        help='show ospfd/ospf6d database status')
parser.add_argument('--ospf_info', action=ospfDumpInfo, nargs='*',
                    metavar=('[v4 | v6 | all]'),
                    help='show ospf setting and neighbor status')
parser.add_argument('--ospf_nbr', action=ospfDumpNbrs, nargs='*',
                    metavar=('[v4 | v6 | all]'),
                    help='show ospf neighbors')
parser.add_argument('--bfdd_dump', action=bfdDumpAction, nargs=0, help='show bfd db status')
parser.add_argument('--bfd_info', action=bfdDumpInfo, nargs='*',
                    default="all all", metavar=('[all | segment-id]', '[v4 | v6 | all]'),
                    help='show bfd config and peer status')
parser.add_argument('--enable_netflow', action=enableNetflow, nargs=3, metavar=('Collector', 'port', 'source_interface'), help='enable Netflow exporter')
parser.add_argument('--disable_netflow', action=disableNetflow, nargs=0, help='disable Netflow exporter')
parser.add_argument('--interfaces', action=interfaceDumpAction, nargs=0,
                    help='show configured interfaces')
parser.add_argument('--ifaces', action=ifaceDumpAction, nargs='*',
                    metavar=('name=<str>|descr=<str>|driver=<str>|netdev=<str>|'
                             'mgmt_type=<str>|encap_type=<str>|oper_state=<str>|'
                             'ifindex=<int>'),
                    help='Show interfaces')
parser.add_argument('--query_interfaces', action=interfaceQueryAction, nargs=0,
                    help='Query the kernel about interfaces')
parser.add_argument('--edge_peers', action=edgePeerInfoDump, nargs=0, help='Dump all peers subnets and gateway association')
parser.add_argument('--de2e_delete', action=edgeDeleteTunnel, nargs=1, metavar=('[vceid]'), help='Tear down dynamic tunnels to the specified edge')
parser.add_argument('--de2e_print', action=edgeDumpDe2eList, nargs='*', default='all',
                    metavar=('[v4 | v6 | all]'),
                    help='Dump the list of VCEIDs with dynamic direct tunnels')
parser.add_argument('--ip_sla_dump', action=ipSlaDump, nargs=0, help='Dump IP-SLA info')
parser.add_argument('--set_ip_sla_icmp_probe_seq', action=setIpSlaIcmpProbeSeqNo, nargs=1,
                    help='Set IP SLA ICMP probe sequence number between 1 and 65534')
parser.add_argument('--ospf_view', action=ospfViewDump, nargs='*',
    #default="all all all", metavar=('[all | prefix]', '[all | segId]', '[all | v4 | v6]'),
    help='dump the ospf view. Options can be [all | dip], [all | ip_fam (v4 | v6)], [all | segid]')
parser.add_argument('--ospf_sync_list', action=ospfSyncViewDump, nargs='*',
                    metavar=('[all | v4 | v6]'),
                    help='Dump OSPF Sync view entries')
parser.add_argument('--bgp_sync_list', action=bgpSyncViewDump, nargs=1, help='Dump BGP Sync view entries')
parser.add_argument('--bgpd_dump', action=bgpDumpAction, nargs=0, help='show bgp db status')
parser.add_argument('--bgp', action=bgpInfoDumpAction, nargs='*',
                    help='Shows BGP operational data')
parser.add_argument('--bgp_view', action=bgpViewDump, nargs='*',
                    help='dump the bgp view. Now segment aware. options can be'
                         '[all | dip], [all | segid], [all | ip_fam (v4 | v6)]')
parser.add_argument('--bgp_view_summary', action=bgpNeighborSummaryDump, nargs='*',
                    metavar=('[v4 | v6 | all]'), help='dump the bgp view summary')
parser.add_argument('--nvs_lb_table', action=nvsLbTableDump, nargs=0, help='Show NVS LB table')
parser.add_argument('--ospf_redis_dump', action=ospfRedisDump, nargs='*',
        help='dump the ospf redis view. options can be [all | dip] [v4 | v6 | all] [all | segId]'
        'dip option needs to specify the exact subnet prefix in slash '
        'notation to work and default is /32 for v4 and /128 for v6')
parser.add_argument('--ospf_agg_dump', action=ospfAggDump, nargs='*',
                    metavar=('[all | dip], [all | seg_id], [all | ip_fam (v4 | v6)]'),
                    help='dump the ospf Aggregate table. options can be '
                    '[all | dip], [all | segid] [all | v4 | v6)]')
parser.add_argument('--bgp_redis_dump', action=bgpRedisDump, nargs='*',
                    help='dump the bgp redis view. options can be [all | dip], [all | segid],'
                         ' [all | v4 | v6].dip option needs to specify the exact subnet prefix in'
                         ' slash notation to work and default is /32 for v4 and /128 for v6')
parser.add_argument('--bgp_agg_dump', action=bgpAggDump, nargs='*',
                    metavar=('[all| dip], [all | segid], [all | v4 | v6]'),
                    help='dump the bgp agg view. options can be [all | dip], [all | segid],'
                         ' [all | v4 | v6].dip option needs to specify the exact subnet prefix in'
                         ' slash notation to work and default is /32 for v4 and /128 for v6')
parser.add_argument('--advertise_ospf_prefix', action=advertiseOspfPrefix,
                    nargs=2,
                    metavar=('[all | prefix]', '[0 | 1]'),
                    help='Debug option to advertise OSPF prefix to VCG')
parser.add_argument('--advertise_bgp_prefix', action=advertiseBgpPrefix, nargs=3,
                    metavar=('[all | IPv4 prefix] [0 | 1] [all | segment-id]'),
                    help='Debug option to advertise BGP prefix to VCG')
parser.add_argument('--advertise_bgp6_prefix', action=advertiseBgp6Prefix, nargs=3,
                    metavar=('[all | IPv6 prefix] [0 | 1] [all | segment-id]'),
                    help='Debug option to advertise BGP6 prefix to VCG')
parser.add_argument('--nht_regis_dump', action=nhtRegistrationDebugDump,
                    default='all all all',
                    nargs='*', metavar=('[all | prefix] [all | segment-id] [all | v4 | v6]'),
                    help='dump the NHT registration list')
parser.add_argument('--bgp_local_ip_dump', action=bgpLocalIpDebugDump, nargs=2, metavar=('[all|prefix]', '[all|segment-id]'), help='dump the BGP Local IP list')
parser.add_argument('--bfd_local_ip_dump', action=bfdLocalIpDebugDump, nargs=2,
                   metavar=('[all|prefix]', '[all|segment-id]'), help='dump the BFD Local IP list')
parser.add_argument('--bfd6_local_ipv6_dump', action=bfd6LocalIpv6DebugDump, nargs=2,
             metavar=('[all|prefix]', '[all|segment-id]'), help='dump the BFD6 Local IPv6 list')
parser.add_argument('--tgw_peer_routes_list_dump', action=tgwPeerRouteListDump, nargs=2,
            metavar=('[all|prefix]', '[all|segment-id]'), help='dump the TGW Peer Routes list')
parser.add_argument('--resolve_route', action=getResolvedRouteDebug, nargs=2, metavar=('[prefix]', '[all|segment-id]'), help='dump the result of Recursive NH Resolution')
parser.add_argument('--add_routes', action=addRoutes, nargs=1,
                   metavar=('[path to input routes json]'), help='add BGP routes to RIB and FIB')
parser.add_argument('--del_routes', action=delRoutes, nargs=2,
                   metavar=('[path to input routes json]', '[fib|all]'),
                   help='del BGP routes from RIB and/or FIB')
parser.add_argument('--stale_flow_dump', action=StaleFlowDumpAction, nargs='?', default="all", metavar=('[all | dest-ip]'), help='dump the current flow table entries')
parser.add_argument('--stale_td_dump', action=StaleTdDumpAction, nargs=0, help='Dump the list of stale Tds')
parser.add_argument('--stale_pi_dump', action=StalePiDumpAction, nargs=0, help='Dump the list of stale Pi')
parser.add_argument('--route_event_stats', action=routeEventStatsAction, nargs='?', default="all", metavar=('[all | logical_id]'), help='request route event stats for peer <logical_id>')
parser.add_argument('--route_stats', action=routeStatsAction, nargs=4,
                    metavar=('[src_id]', '[all|nhop_id]', '[all|seg]', '[all|route_type]'),
                    help='request route stats for routes originated by <src_id>,'\
                         ' with nexthop <nhop_id> for segment <seg>')
parser.add_argument('--pkt_tracker', action=PacketTracker, nargs=6, metavar=('[any|sip]', '[any|sport]','[any|dip]','[any|dport]', '[any|proto]', '[count of packets]'), help='Track the life cycle of a flow')
parser.add_argument('--reload_configs', action=reloadConfigs, nargs=0, help='reload configs that can be reloaded without requiring edge/gw restart')
parser.add_argument('--user_peer_dump', action=userPeerDumpAction, nargs=0, help='Dump VeloCloud Peers for Remote Diagnostics')
parser.add_argument('--user_path_dump', action=userPathDumpAction, nargs='+',
                    metavar=('[all | Gateway | Edge Name/logical_id]',
                    '[include_sub_path[0 | 1]]' '[show_only_hub_cluster_ic_tun[0 | 1]]'),
                    help='Dump VeloCloud Paths for Remote Diagnostics')
parser.add_argument('--user_flow_dump', action=userFlowDumpAction, nargs='*',
                    default = ['all', 'all', 'all', 'all', 'all', 'all', 'all'],
                    metavar=('[all | seg-id] [all | src-ip] [all | src-port] [all | dest-ip]'
                             ' [all | dest-port] [max flows to display] [all | v4 | v6]'),
                    help='user dump of the current flow table entries')
parser.add_argument('--user_firewall_dump', action=userFirewallDumpAction, nargs='*',
                    default = ['all', 'all', 'all', 'all', 'all', 'all', 'all'],
                    metavar=('[all | seg-id] [all | src-ip] [all | src-port] [all | dest-ip]'
                             ' [all | dest-port] [max flows to display] [all | v4 | v6]'
                             ' [efs-rule] [allow | block]'),
                    help='user dump of the current firewall entries')
parser.add_argument('--user_flow_flush', action=userFlowFlushAction, nargs=2, metavar=('[all | src-ip]', '[all | dest-ip]'), help='user flush of the current flow table entries')
parser.add_argument('--user_firewall_flush', action=userFirewallFlushAction, nargs=2, metavar=('[all | src-ip]', '[all | dest-ip]'), help='user flush of active firewall sessions')
parser.add_argument('--malloc_trim', action=mallocTrim, nargs=0, help='run malloc_trim')
parser.add_argument('--malloc_stats', action=mallocStats, nargs=0, help='run malloc_stats')
parser.add_argument('--flow_ager_toggle', action=toggleFlowAgerAction, nargs='+', metavar=('[enable_or_disable] [timer_iterval_secs] [idle_timeout_secs]'), help='enable/disable flow ager --flow_ager_toggle [1|0:enable/disable] [timer_iterval_secs=<value in seconds] [idle_timeout_secs=<idle timeout in seconds]')
parser.add_argument('--memory_dump', action=memoryDebugDump, nargs=0, help='Dump the current unknown allocations')
parser.add_argument('--pmtud_dump', action=dumpPlpmtudMTU, nargs='?', default="all", metavar=('[all] | peer_name | td_version | interface'), help='show MTU detected by PLPMTUD module')
parser.add_argument('--pmtud_run', action=runPmtudOnAllPaths, nargs='?', default="all", metavar=('[all] | peer_name | td_version | interface'), help='Force MTU probing on all paths')
parser.add_argument('--udp_hole_punching', action=udpHolePunchingDump, nargs=0, help='Dump UDP hole punching probe data')
parser.add_argument('--pnat_1to1', action=bizPnatOneToOneDumpAction, nargs='*',
                    help='Usage: [all | segment-id] [v4 | v6 | all]; '\
                    'dump biz policy 1:1 NAT rules')
parser.add_argument('--memory_leak', action=memoryLeak, nargs=1, metavar=('[num of MB to leak]'), help='deliberately cause memory to be leaked inside edged')
parser.add_argument('--pr_dump', action=PRDumpAction, nargs=1, metavar=('[logical-id | all]'), help='dump the reachability info')
parser.add_argument('--peer_stats', action=PRStatsDump, nargs='*',
        default=['all','all'],metavar=('[ <peer_id> | all ]',
            '[detailed | all]'), help='peer stats displays the stats '\
            'for each   peer and the detailed option displays the path '\
            'stats for each tunnel along with the peer info')
parser.add_argument('--dpdk_ports_dump', action=dpdkPortsDump, nargs='*',
                    metavar=('[interface physical name]'),
                    help='Dump dpdk port information')
parser.add_argument('--dpdk_bond_dump', action=dpdkBondDump, nargs=1, metavar=('[interface physical name]'),
                    help='Dump dpdk bond information')
parser.add_argument('--dpdk_xstats_dump', action=dpdkXstatsDump, nargs='*',
                    metavar=('[intf [reset]]')),
parser.add_argument('--crypto-test', action=cryptoTestAction, nargs=1, help='Run a crypto test on the path(s) connected through an interface')
parser.add_argument('--configure_nsd_bgp', action=configureNsdBgpAction, nargs=1,\
                    help='Configure NSD BGP on edge - Unsupported')
parser.add_argument('--cluster_info', action=clusterInfoDump, nargs=0, help='Dump clustering information')
parser.add_argument('--cluster_rebalance', action=clusterRebalanceHub, nargs=1, metavar=('[rebalance_type]'),
                    help='[include-self] to trigger uniform distribution of spokes in cluster and [exclude-self] to exclude hub and trigger uniform distribution')
parser.add_argument('--fw_local_logging', action=firewallLocalLogging, nargs=1,
                    metavar=('[enable|disable|status]'),
                    help='[enable] to enable local logging, [disable] to disable local\
                            logging and [status] to get the current local logging status')
parser.add_argument('--cluster_static_routes', action=clusterStaticRouteDump,
                    default='all all all', nargs='*',
                    metavar=('[all|prefix] [all|segment-id] [all|v4|v6]'),
                    help='dump the cluster static routes table')
parser.add_argument('--lan_side_nat', action=lanSideNatDumpAction, nargs=0, help='Dump the LAN-side NAT rules')
parser.add_argument('--reinit_routes', action=routeInitReqAction, nargs='?', default="all", metavar=('all | segment-id'), help='request route init for segment [seg_id] i.e. sync routes in segment [seg_id] to/from all gateways')
parser.add_argument('--health_report', action=getHealthReport, nargs=0, help='Dump health information')
parser.add_argument('--vcrp_win_reopen', action=vcrpReopen, nargs=1, metavar=('<logical_id>'), help='reopen window')
parser.add_argument('--rmsg_win_reopen', action=rmsgReopen, nargs=1, metavar=('<logical_id>'), help='reopen window')
parser.add_argument('--segments', action=segmentDumpAction, nargs='*', help='show configured segments. Supports "--segments [vpn|gateway|controller]" options')
parser.add_argument('--vpn_test', action=vpnTestAction, nargs = 1, metavar=('[seg-id|all]'), help ='Performing a segment aware VPN test')
parser.add_argument('--nvs_list', action=nvsListAction, nargs=0, help='dump all the current NVS path status')
parser.add_argument('--l7_health_checks', action=l7HealthCheckListAction, nargs=0,
                    help='dump all the current Zscaler L7 health checks configured')
parser.add_argument('--report_l7_health_check', action=l7HealthCheckReportAction, nargs=6,
                    metavar=('<seg-id>', '<nvs-logical-id>', '<link-logical-id>', '<dest-id>',
                             '<l7-success>', '<rtt_ms>'),
                    help='Report L7 health check results')
parser.add_argument('--l7_health_check_tbl_add', action=l7HealthCheckTblAddAction, nargs=6,
                    metavar=('<seg-id>', '<dest-ip>', '<nvs-logical-id>',
                              '<link-logical-id>', '<nvs-ip>', '<dst-port>'),
                    help='Insert entry to L7 health check hash table')
parser.add_argument('--l7_health_check_tbl_del', action=l7HealthCheckTblDelAction, nargs=3,
                    metavar=('<seg-id>', '<dest-ip>', '<dst-port>'),
                    help='Delete entry from L7 health check hash table')
parser.add_argument('--l7_health_check_tbl_dump', action=l7HealthCheckTblDumpAction, nargs=0,
                    help='Dump entry from L7 health check hash table')
parser.add_argument('--l7_health_check_tbl_flush', action=l7HealthCheckTblFlushAction, nargs=0,
                    help='Flush all the entries from L7 health check hash table')
parser.add_argument('--mcr_dump', action=mcrDumpAction, nargs=0, help='dump all multicast routes')
parser.add_argument('--profile_dump', action=profileDump, nargs=0,  help='Dump the profiles for the enterprise')
parser.add_argument('--edge_list', action=edgeListDump, nargs=0,  help='Dump the profiles for the enterprise')
parser.add_argument('--edge_cluster_table', action=edgeClusterDump, nargs=0,
                    help='Dump the edge cluster mapping table')
parser.add_argument('--cluster_edge_table', action=clusterEdgeDump, nargs=0,
                    help='Dump the cluster to edge mapping table')
parser.add_argument('--pimd_dump', action=pimdDump, nargs=0, help='dump pimd status')
parser.add_argument('--igmp_dump', action=igmpDump, nargs=0, help='dump igmp info')
parser.add_argument('--pim_neighbor', action=pimNeighborDump, nargs=0, help='dump the pim neighbor summary')
parser.add_argument('--set_link_state_up', action=linkStateUp, nargs=1, metavar=('[interface logical name]'),
                    help='Set internal link state UP')
parser.add_argument('--set_link_state_down', action=linkStateDown, nargs=1, metavar=('[interface logical name]'),
                    help='Set internal link state DOWN')
parser.add_argument('--vnf', action=vnfDumpAction, nargs=0, help='dump vnf info')
parser.add_argument('--radius_on_routed', action=radiusRoutedDebugDumpAction, nargs=0,
                    help='dump debug info for RADIUS on routed interfaces')
parser.add_argument('--radius_on_lan', action=radiusLanDebugDumpAction, nargs=0,
                    help='dump debug info for RADIUS on lan bridge interfaces')
parser.add_argument('--set_dbg_mc_state_up', action=dbgMcStateUp, nargs=1, metavar=('[seg-id]'),
                    help='Set MC state UP on vce1 interface for MC testing')
parser.add_argument('--set_dbg_mc_state_down', action=dbgMcStateDown, nargs=1, metavar=('[seg-id]'),
                    help='Set MC state DOWN on vce1 interface for MC testing')
parser.add_argument('--port_screen_dump', action=portScreenDump, nargs=0, help='Dump optional Port Scan Screening configuration')
parser.add_argument('--set_stale_route_timeout', action=setStaleRouteTimeout, nargs=1, metavar=('[timeout]'), help='Stale Refresh timeout in mins <1-60>')
parser.add_argument('--cpu_metric_debug', action=setUnsetCpuMetric, nargs='*',
                    help='<reset>|<set N>: reset cpu value | set cpu value for testing health stats. This command is unavailable in GA builds.')
parser.add_argument('--wan_hb_suppress', action=haWanHbSuppress, nargs=1, metavar=('[value]'),
                    help='Non-zero value suppresses wan interface heartbeats for High Availability (Not Recommended)')
parser.add_argument('--ofc_config', action=displayOfcConfig, nargs='*', help='Displays the default ofc_config')
parser.add_argument('--cws_pol_dump', action=cwsPolicyDump, nargs=0, help='Show cws policy config')
parser.add_argument('--ping', action=pingAction, nargs=3, metavar=('<src-ip | src-ifname>', '<dest-ip | dest-hostname>', '<seg-id>'), help='Ping utility')
parser.add_argument('--traffic_gen', action=trafficGeneratorAction, nargs=0,
                    help='Generates and sends network packets')
parser.add_argument('--seg_nat_add', action=segNatAddAction, nargs=6, metavar=('app-name', '<seg-id>', '<dest-ip>', '<dport>', '<protocol>', '<iface_name>'), help='Add static entry to segment NAT table')
parser.add_argument('--seg_nat_flush', action=segNatFlushAction, nargs=1, metavar='app_name', help='Flush all entries of the designated app in segment NAT table. Avaliable app_name: RSYSLOG | SNMP | ANALYTICS | TACACS')
parser.add_argument('--seg_nat_dump', action=segNatDump, nargs=0, help='Dump the segment NAT table')
parser.add_argument('--dynbw_config_dump', action=dynBwConfigDump, nargs=0, help ='Dump the dynamic bandwidth config info')
parser.add_argument('--packet_pair_debug', action=ppDebugDump, nargs=2, metavar=('<tx|rx>', '<peer_logical_id>'), help = 'Dump the packet pair debug info for tx and rx.')
parser.add_argument('--cbh-debug', action=cbhDebug, nargs=0, help='Debug CBH')
parser.add_argument('--address_groups', action=addressGroupDebugDump, nargs='*',
                    default='all', metavar=('[v4 | v6 | all]'),
                    help='Dump the list of address groups configured on VCO')
parser.add_argument('--port_groups', action=portGroupDebugDump, nargs=0, help='Dump the list of port groups configured on VCO')
parser.add_argument('--get_vnf_ha_state', action=getVnfHaState, nargs=0, help='Obtains the current VNF HA state on the edge')
parser.add_argument('--vnf_ha_suppress', action=vnfHaSuppress, nargs=1, help='Non-zero value disregards the vnf instance state for High Availability')
parser.add_argument('--denylist_dump', action=denylistTblDump, nargs=0,
                    help='Dump the table of Denylisted source IPs')
parser.add_argument('--halfopen_dump', action=halfopenDump, nargs=0,
                    help='Dump the table of halfopen connection counts per destination IP')
parser.add_argument('--session_table_summary', action=sessionTableSummary, nargs=0,
                    help='Shows a count of active and stale sessions');
parser.add_argument('--connectivity_mac_dump', action=connectivityDump, nargs=0,
                    help='Shows entries in the connectivity mac table');
parser.add_argument('--load_local_config', action=loadLocalConfig, nargs=0,
                                    help='load config from /root/config.json')
parser.add_argument('--suricata_stats_dump', action=suricataStatsDump, nargs=0,
                                    help='Fetch stats from Suricata module')
parser.add_argument('--suricata_config_dump', action=suricataConfigDump, nargs=0,
                                    help='Fetch config paramters from Suricata module')
parser.add_argument('--nyansa_ep_nat_dump', action=nyansaEpNatDump, nargs=0,
                    help='Dump  Nyansa End point array and src IP used for NATing special src IP')
parser.add_argument('--nd6_set_queue_limit', action=nd6QueueLimit, nargs=1,
                    metavar=('[limit]'), help='Set queue limit per neighbor')
parser.add_argument('--ra_view', action=raViewDump, nargs=0, help='dump the ra view.')
parser.add_argument('--update_ra_host_config', action=updateRAHostConfig,
                    help='Update interface RA host configuration', nargs=3,
                    metavar=('<interface>', '<subif_idx>','<file_path>'))
parser.add_argument('--ra_host_config', action=raHostConfigDump, nargs=0,
                    help='Dump interface RA hosts configurations')
parser.add_argument('--self_ip_dump', action=selfIpDump, nargs='*', default="all",
                    metavar=('[v4 | v6 | all]'), help='dump the self ip table')
parser.add_argument('--dpt_profile_mode', action=dptSetProfileModeAction, nargs = 1,
                    metavar=('[precise|imprecise]'),
                    help='Enable or disable precise profiling of DP tasks')
parser.add_argument('--dpt_top', action=dptCoreStatsAction, nargs = '?',
                    metavar=('[core-id|all]'), help='Show DP core stats')
parser.add_argument('--cpuset', action=cpusetAction, nargs=0,
                    help='dump thedp and non dp cpuset')
parser.add_argument('--dpt_set_max_work', action=dptSetMaxWorkAction, nargs = 3,
                    metavar=('<core-id|all>', '<match>', '<max_work>'),
                    help='Set max work for a DP task')
parser.add_argument('--fdisp_flow_dump', action=flowDispatcherFlowDumpAction, nargs = '*',
                    metavar=('core_id=<int>|type=<str>|protocol=<int>|ip_tos=<int>|'
                             'src_port=<int>|dst_port=<int>|src_ip=<str>|dst_ip=<str>|'
                             'ifindex=<int>|discr=<int>|discr_type=<int>'),
                    help='Show flow-dispatcher flows')
parser.add_argument('--fdisp_profile_mode',
                    action=flowDispatcherSetProfileModeAction, nargs = 1,
                    metavar=('[precise|imprecise]'),
                    help='Enable or disable precise profiling of flow-dispatcher')
parser.add_argument('--fdisp_top', action=flowDispatcherDumpAction, nargs = '?',
                    metavar=('[core-id|all]'), help='Show flow dispatcher stats')
parser.add_argument('--transient_td_dump', action=TransientTdDumpAction,
                    nargs='*', help='Dump the list of transient Tds or only the count')
parser.add_argument('--ike_tunnel_debug', metavar=('clear | <src-ip> <dest-ip> <level>'),
                    nargs='*', action=ikeTunnelDebug, help='Enable per-tunnel debugging for a '\
                    'given endpoint or disable it with the clear command')
parser.add_argument('--per_peer_debug', metavar=('clear | <any|cookie> <sip> <dip>'),
                    nargs='*', action=perPeerDebug, help='Enable per-peer debugging for a'\
                    'given cookie in hex and endpoint or disable it with the clear command')
parser.add_argument('--fdisp_hash_table_stats', action=flowDispatcherHashTableStatsAction,
                    nargs = '?', metavar=('[core-id|all]'),
                    help='Show flow dispatcher hash table stats')
parser.add_argument('--rss_hash_calc', action=rssHashCalcAction, nargs = 5,
                    metavar=('<src_ip>', '<src_port>', '<dst_ip>', '<dst_port>', '<protocol>'),
                    help='Calculate the RSS hash for a src/dst pair')
parser.add_argument('--queue_top', action=queueTopAction, nargs = '?',
                    metavar=('<sort_column>'), help='Show queue statistics')
parser.add_argument('--iface_top', action=ifaceTopAction, nargs = '?',
                    metavar=('<sort_column>'), help='Show interface statistics')
parser.add_argument('--sor_dump', action=sorDump, nargs='?', default="all",
                    metavar=('[all | <node_id>]'),
                    help='Dump SoR entries')
parser.add_argument('--stt_dump', action=sttDump, nargs='?', default="all",
                    metavar=('[all | <transit_log_id>]'),
                    help='Dump STT entries')
parser.add_argument('--de2e_subscribers_dump', action=de2eSubDump, nargs=0,
                    help='Dump Dymaic E2E subscribers entries')
parser.add_argument('--flow_top', action=flowTopAction, nargs = '*',
                    metavar=('<sort_column>|delay_secs=<secs>|max_flows=<num>'),
                    help='Show top flows')
parser.add_argument('--flow_hash_table_stats', action=flowHashTableStats, nargs=0,
                    help='Show flow hash table statistics')
parser.add_argument('--nat_hash_table_stats', action=natHashTableStats, nargs=0,
                    help='Show nat hash table statistics')
parser.add_argument('--nat_port_hash_table_stats', action=natPortHashTableStats, nargs=0,
                    help='Show nat port hash table statistics')
parser.add_argument('--flow_fdisp_dump', action=flowFdispDump, nargs=1,
                    metavar=('[<flowId>]'),
                    help='Dump flow dispatcher flows associated with particular fc')
parser.add_argument('--shr', action=toggleShrAction, nargs='+',
                    metavar=('[enable|disable] [stats_interval_ms]'),
                    help='[1|0:enable/disable] [stats_interval_ms=route stats interval in ms]')
parser.add_argument('--config_status', action=moduleVersionDump, nargs=0,
                    help='Dump per module config version')
parser.add_argument('--ctx_dump', action=ContextLogAction, nargs=0,
                    help='dumps the context buffer information of threads')
parser.add_argument('--ctx_log_toggle', action=ContextLogAction, nargs=2,
                    metavar=('[all|TID] [1|0]'),
                    help='[all|TID:all or Thread ID] [1|0:Enable/Disable]')
parser.add_argument('--hostapd_acl_check', action=hostapdACLCheck, nargs=2,
                    metavar=('<interface>','<mac>'),
                    help='Check hostapd ACL status for MAC address');
parser.add_argument('--hostapd_acl_delete', action=hostapdACLDelete, nargs=2,
                    metavar=('<interface>','<mac>'),
                    help='Delete hostapd ACL entry for MAC address');
parser.add_argument('--ha_reset_failover', action = haResetFailover, nargs = 0,
                   help ='Reset the HA failover time back to the original value')
parser.add_argument('--metric_table_dump', action=metricTableDump,
                   default='all all',
                   nargs='*',
                   metavar=('[all|logical_id] [all|segment-id]'),
                   help='Dump Transit Metric Table')
parser.add_argument('--auto_sim_switch', action=autoSimSwitchDumpAction, nargs=0,
                   help='show auto SIM switch status')
parser.add_argument('--upgrade_status', action = upgradeStatus, nargs = 0,
                   help ='Prints the upgrade status')
parser.add_argument('--mh_vcrp_dest_info_dump', action=edgeDestInfoDump, nargs='*',
                    help='Dump all dest info with subscribers info')
parser.add_argument('--pd6_dump', action=DHCP6PDDump, nargs=0,
                    help='Dump DHCP PD6 Hash Table')
parser.add_argument('--uuid_cache_free_cnt', action=uuidCacheFreeCntAction, nargs=0,
                    help='Display the free count of uuid cache')
parser.add_argument('--atp_profile', action=ATPProfiling, nargs=1,
                    help='Enable/Disable ATP Profiling')
parser.add_argument('--atp_profile_dump', action=ATPProfilingDump, nargs=0,
                    help='ATP Profiling Dump')
parser.add_argument('--efs_url_lookup', action=URLReputationRemDiag, nargs=1,
                    help='Fetch Web Reputation & category for a given URL')
parser.add_argument('--ip_threat_lookup', action=IPThreatDump, nargs=1,
                    help='Fetch IP threat score for a given IP')
parser.add_argument('--webroot_set_loglevel', action=WebrootSetLogLevel, nargs='*',
                    help='Set Webroot log level. Usage:'\
        ' --webroot_set_loglevel [1|2|3|4|5] [edge_only|bcti_only|both]'\
        ' loglevel: Error=1, Warning=2, Info=3, Debug=4, Trace=5'\
        ' logging_type:'\
        '         edge_only -> edged.log or dbgctl'\
        '         bcti_only -> all logs got to bcti.log only'\
        '         both -> all logs got to edge|dbgctl and bcti.log'\
        '             note: bcti_only and both can impact performance\n')
parser.add_argument('--wrsdk_status', action=WebrootSdkStatus, nargs=0,
                    help='Webroot SDK Status')
parser.add_argument('--url_fc_hash_table_stats', action=efsUrlFcHashTableStats, nargs=0,
                    help='Show EFS URL FC hash table statistics')
parser.add_argument('--client_connector', action=clientConnector, nargs='*',
                    metavar=('[status|dump|restart|set_max_cpu_percent]|'\
                             '[info|ip|status|version|percent_value]'),
                    help='Client Connector status|dump|restart')
parser.add_argument('--show_edge_wss_conf', action = showEdgeWssConf, nargs='?',
                    help='Show the edge wss configuration')
parser.add_argument('--config_wss_test', action=configWssTest, nargs=1,
                    help='give json file to parse')
parser.add_argument('--config_wss_biz_test', action=configWssBizTest, nargs=1,
                    help='give json file to parse')
parser.add_argument('--sched_xstats', action=schedXstatsAction, nargs=1,
                    metavar=('[enable|disable]'),
                    help='Enable/Disable scheduled extended statistics')
parser.add_argument('--lacp_info', action=showLacpInfo, nargs='*', metavar=('[all|<iface_name>]'),
                    help='Show LACP protocol status info')
parser.add_argument('--lacp_stats', action=showLacpStats, nargs='*',
                    metavar=('[all|<iface_name>]'), help='Show LACP stats')
parser.add_argument('--lacp_slaves', action=showLacpSlaves, nargs='*',
                    metavar=('[all|<iface_name>]'), help='Show LACP active slaves')
parser.add_argument('-t', '--time', action='store_true', help='Append time to output')
parser.add_argument('--limit_ctrl_traffic_frequency', action=limitCtrlTrafficDebugDump, nargs='*',
                    help='ctrl traffic limit status|clock_sync_interval_min|disable_hb_probe|'\
                         ' traffic_hb_ms')

class SYSPARAMS(object):
    pass

if __name__ == '__main__':
    try:
        sysparams = SYSPARAMS()
        sysargs = sysparser.parse_known_args(namespace=sysparams)
        rpc_client = rpc.get_local_rpc_client(None, 'tcp://127.0.0.1:26464',
                                            log_requests=False, timeout=USER_TIMEOUT_SECS)
        remote_server = rpc_client.get_proxy()

        signal.signal(signal.SIGALRM, handler)
        signal.alarm(USER_TIMEOUT_SECS)
        args = parser.parse_args()
        # Log time if requested via -t
        if args.time:
            print(log_datetime())
        # Log the command
        if os.getenv('DIAG_BUNDLE') != 'True':
            try:
                logname = utils.getlogname()
            except OSError:
                logname = pwd.getpwuid(os.getuid())[0]
            syslog.syslog((syslog.LOG_INFO|syslog.LOG_USER),
                        "(user=%s) %s" % (logname, " ".join(sys.argv[1:])))
        sys.exit(0)
    except rpc.CommunicationError as e:
        print("Server was not listening")
        sys.exit(1)
    except RPCError as e:
        print("RPC error: ", e)
        sys.exit(1)
