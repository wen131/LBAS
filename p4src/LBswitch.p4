/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define HASH_CONST 6
#define HASH_CONST_BIT 5
#define MAX_DIP_BIT 4
#define MAX_DIP_NUM 16
#define VER_BIT 6
#define MAX_ROUTE_NUM 2048

#define CONTROLLER_SESSION_ID 250
#define SPECIAL_SRC_MAC 723

#define HOST_PORT 0
#define SERVER_MAC 255


header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

#define IP_PROT_TCP 0x06

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(m_metadata.tcpLength, ipv4.totalLen - 20);
    return select(ipv4.protocol) {
        IP_PROT_TCP : parse_tcp;
        default : ingress;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return ingress;
}

field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        m_metadata.tcpLength;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags;
        tcp.window;
        tcp.urgentPtr;
        payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    verify tcp_checksum if(valid(tcp));
    update tcp_checksum if(valid(tcp));
}

action _drop() {
    drop();
}

header_type custom_metadata_t {
    fields {
        num: MAX_DIP_BIT;
        mod: HASH_CONST_BIT;
        hash: 16;
        mac: 48;
        ip: 32;
        port: MAX_DIP_BIT;
        version: VER_BIT;
        tcpLength: 16;
    }
}

metadata custom_metadata_t m_metadata;

action nat() {
    modify_field(ipv4.dstAddr, m_metadata.ip);
    modify_field(standard_metadata.egress_spec, m_metadata.port);
    add_to_field(ipv4.ttl, -1);
    modify_field(ethernet.dstAddr, m_metadata.mac);
}

// TODO: Define the field list to compute the hash on
// Use the 5 tuple of 
// (src ip, dst ip, src port, dst port, ip protocol)

field_list hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}

field_list_calculation hash_cal {
    input { 
        hash_fields;
    }
    algorithm : crc16;
    output_width : 16;
}

counter request_counter {
    type: packets;
    direct: map_table;
}

action select_dip(dip_num) {
    modify_field(m_metadata.num, dip_num);
}

action hash_action(){
    modify_field_with_hash_based_offset(m_metadata.mod, 0,hash_cal, HASH_CONST);
    modify_field_with_hash_based_offset(m_metadata.hash, 0, hash_cal, 65536);
}

action select_version(ver){
    modify_field(m_metadata.version, ver);
}

action map_dip(ip, mac, port){
    modify_field(m_metadata.ip, ip);
    modify_field(m_metadata.mac, mac);
    modify_field(m_metadata.port, port);
}

field_list remember_fields {
    standard_metadata;
    m_metadata.hash;
}

register version_register {
    width: VER_BIT;
    instance_count: 1;
}

action remember_action(){
    clone_ingress_pkt_to_egress(CONTROLLER_SESSION_ID, remember_fields);
    register_read(m_metadata.version, version_register, 0);
}

action inverse_nat(vip){
    modify_field(ipv4.srcAddr,vip);
    modify_field(ethernet.srcAddr,SERVER_MAC);
    modify_field(standard_metadata.egress_spec, HOST_PORT);
}

action _nop(){
}

// TODO: Define the tables to run actions
table innat_table {
    reads {
        ipv4.srcAddr : exact;
    }
    actions {
        inverse_nat;
    }
    size : MAX_DIP_NUM;
}

table hash_table {
    actions {
        hash_action;
    }
    size: 1;
}

table version_table {
    reads {
        m_metadata.hash : exact;
    }
    actions {
        select_version;
    }
    size: 65536;
}

table remember_version {
    actions {
        remember_action;
    }
    size: 1;
}

table route_table {
    reads {
        m_metadata.mod : exact;
        m_metadata.version : exact;
    }
    actions {
        select_dip;
    }
    size: MAX_ROUTE_NUM;
}

table map_table {
    reads {
        m_metadata.num : exact;
    }
    actions {
        map_dip;
    }
    size: MAX_DIP_NUM;
}

table forward {
    actions {
        nat;
    }
    size: 1;
}

control ingress {
    apply(innat_table){
        miss{
            apply(hash_table);
            apply(version_table){
                miss{
                    apply(remember_version);
                }
            }
            apply(route_table);
            apply(map_table);
            apply(forward);
        }
    }
}


action push_to_controller() {
    modify_field(ethernet.srcAddr, SPECIAL_SRC_MAC);
    modify_field(ethernet.dstAddr, m_metadata.hash);
}

table redirect {
    reads {
        standard_metadata.instance_type : exact;
    }
    actions {
        _nop;
        push_to_controller;
    }
    size: 1;
}

control egress {
    apply(redirect);
}
