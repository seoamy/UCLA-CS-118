/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::processPacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown. Dropping packet..." << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  std::string macAddress = macToString(packet);
  std::string ifaceAddress = macToString(iface->addr);
  std::string broadcastAddress = "FF:FF:FF:FF:FF:FF";
  std::string lowerBroadcastAddress = "ff:ff:ff:ff:ff:ff";

  // check if mac address is arp broadcast address or matches iface address
  if ((macAddress != broadcastAddress) && 
      (macAddress != ifaceAddress) && 
      (macAddress != lowerBroadcastAddress)) {
        std::cerr << "Packet received. Packet ignored due to not matching the broadcast address nor interface address. Dropping packet..." << std::endl;
        return;
  }

  // get packet type
  uint16_t packet_ethertype = ethertype(packet.data());

  // ARP packet
  if (packet_ethertype == ethertype_arp) {
    std::cerr << "ARP packet type" << std::endl;
    const arp_hdr* arp_header = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));

    uint16_t arp_op = ntohs(arp_header->arp_op);

    // received ARP request
    if (arp_op == arp_op_request) {
      std::cerr << "***Handle ARP request" << std::endl;

      // lookup target ip address to get mac address in arp cache
      std::shared_ptr<ArpEntry> entry = m_arp.lookup(arp_header->arp_tip);
      if (entry != nullptr) {
        // ethernet response header
        ethernet_hdr eth_hdr_reply;
        memcpy(eth_hdr_reply.ether_dhost, &(arp_header->arp_sha), ETHER_ADDR_LEN);
        memcpy(eth_hdr_reply.ether_shost, entry->mac.data(), ETHER_ADDR_LEN);
        eth_hdr_reply.ether_type = htons(ethertype_arp); 

        // arp response header
        arp_hdr arp_hdr_reply;
        arp_hdr_reply.arp_hrd = htons(arp_hrd_ethernet);
        arp_hdr_reply.arp_pro = htons(ethertype_ip);
        arp_hdr_reply.arp_hln = ETHER_ADDR_LEN;
        arp_hdr_reply.arp_pln = 4;
        arp_hdr_reply.arp_op = htons(arp_op_reply);
        memcpy(arp_hdr_reply.arp_sha, entry->mac.data(), ETHER_ADDR_LEN);
        arp_hdr_reply.arp_sip = iface->ip;
        memcpy(arp_hdr_reply.arp_tha, &(arp_header->arp_sha), ETHER_ADDR_LEN);
        arp_hdr_reply.arp_tip = arp_header->arp_sip;

        // send arp response packet
        Buffer packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        memcpy(packet.data(), &eth_hdr_reply, sizeof(ethernet_hdr));
        memcpy(packet.data() + sizeof(ethernet_hdr), &arp_hdr_reply, sizeof(arp_hdr));
        sendPacket(packet, iface->name);
        std::cerr << "======== SENT arp reply with mac address from arp cache = " << std::endl;
        print_hdrs(packet);
      }
      else if (arp_header->arp_tip == iface->ip) {
      // send mac address of this interface
      // ethernet response header
        ethernet_hdr eth_hdr_reply;
        memcpy(eth_hdr_reply.ether_dhost, &(arp_header->arp_sha), ETHER_ADDR_LEN);
        memcpy(eth_hdr_reply.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        eth_hdr_reply.ether_type = htons(ethertype_arp); 

        // arp response header
        arp_hdr arp_hdr_reply;
        arp_hdr_reply.arp_hrd = htons(arp_hrd_ethernet);
        arp_hdr_reply.arp_pro = htons(ethertype_ip);
        arp_hdr_reply.arp_hln = ETHER_ADDR_LEN;
        arp_hdr_reply.arp_pln = 4;
        arp_hdr_reply.arp_op = htons(arp_op_reply);
        arp_hdr_reply.arp_sip = iface->ip;
        memcpy(arp_hdr_reply.arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(arp_hdr_reply.arp_tha, &(arp_header->arp_sha), ETHER_ADDR_LEN);
        arp_hdr_reply.arp_tip = arp_header->arp_sip;

        // send arp response packet
        Buffer packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        memcpy(packet.data(), &eth_hdr_reply, sizeof(ethernet_hdr));
        memcpy(packet.data() + sizeof(ethernet_hdr), &arp_hdr_reply, sizeof(arp_hdr));
        sendPacket(packet, iface->name);
        std::cerr << "======== SENT arp reply with this interface's mac address = " << std::endl;
        print_hdrs(packet);
      }
      else {
        std::cerr << "Target IP does not match interface IP and is not in ARP cache. Dropping packet..." << std::endl;
        return;
      }
    }

    // received ARP reply
    else if(arp_op == arp_op_reply) {
      std::cerr << "***Handle ARP reply" << std::endl;

      Buffer arp_mac_address(ETHER_ADDR_LEN);
      memcpy(arp_mac_address.data(), arp_header->arp_sha, ETHER_ADDR_LEN);

      // if mapping not in arp table, add it
      if(m_arp.lookup(arp_header->arp_sip) == NULL) {
        std::shared_ptr<ArpRequest> arp_reqs = m_arp.insertArpEntry(arp_mac_address, arp_header->arp_sip);
      
        // handle the requests (send all packets waiting on new mapping) 
        if (arp_reqs != NULL) {
          for(auto itr = arp_reqs->packets.begin(); itr != arp_reqs->packets.end(); itr++) {
            ethernet_hdr *eth_hdr_response = (ethernet_hdr*) itr->packet.data();
            memcpy(eth_hdr_response->ether_dhost, arp_header->arp_sha, ETHER_ADDR_LEN);
            memcpy(eth_hdr_response->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
            sendPacket(itr->packet, itr->iface);
            std::cerr << "======== SENT packet that was awaiting an arp reply mapping = " << std::endl;
            print_hdrs(itr->packet);
          }
        }
      }
    }
    else {
      std::cerr << "Invalid ARP operation. Dropping packet..." << std::endl;
    }
  }

  // IP packet
  else if(packet_ethertype == ethertype_ip) {
    std::cerr << "***IP Packet Type" << std::endl;

    Buffer ip_packet(packet);
    ip_hdr* ip_header = (ip_hdr*) (ip_packet.data() + sizeof(ethernet_hdr));

    // verify min length
    if (packet.size() < (sizeof(ethernet_hdr) + sizeof(ip_hdr))) {
      std::cerr << "IP packet does not meet min IP packet length requirement. Dropping packet..." << std::endl;
      return;
    }

    // verify checksum
    uint16_t checksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;

    if (checksum != cksum(ip_header, sizeof(ip_hdr))) {
      std::cerr << "Invalid IP packet checksum. Dropping packet..." << std::endl;
      return;
    }
  
    // IP version check (must be v4)
    if (ip_header->ip_v != 4) { 
      std::cerr << "Not a valid IPv4 packet. Dropping packet..." << std::endl;
      return;
    }

    // verify should not be dropped by ACL
    uint16_t src_port;
    uint16_t dst_port;

    // if packet is an ICMP packet, both port numbers are 0
    if (ip_header->ip_p == ip_protocol_icmp) {
      src_port = 0;
      dst_port = 0;
    }

    // if packet is TCP/UDP, srcPort and dstPort number should be extracted from
    // the TCP/UDP header which is right behind the IP header
    else {
      memcpy(&src_port, ip_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), 2);
      memcpy(&dst_port, ip_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(uint16_t), 2);
    }

    try {
      ACLTableEntry entry = m_aclTable.lookup(ntohl(ip_header->ip_src), ntohl(ip_header->ip_dst), ip_header->ip_p, ntohs(src_port), ntohs(dst_port));
      // log entry in log file
      m_aclLogFile << entry;
      if (entry.action == "deny") {
        std::cerr << "ACL rule denied this packet. Dropping packet..." << std::endl;
        return;
      }

    } catch(std::runtime_error) {
      // continue forwarding packet if no ACL rule applies
        std::cerr << "No ACL rule matched, continuing..." << std::endl;
    }

    // if destined for router, drop
    if (findIfaceByIp(ip_header->ip_dst) != nullptr) {
      std::cerr << "Dropping packet, it's destined for the router." << std::endl;
      return;
    }

    if (ip_header->ip_ttl == 0) {
      std::cerr << "Time to live is 0. Dropping packet..." << std::endl;
      return;
    }

    // decrement ttl and check if 0
    ip_header->ip_ttl--;
    if (ip_header->ip_ttl == 0) {
      std::cerr << "Time to live is 0. Dropping packet..." << std::endl;
      return;
    } 

    // recompute the checksum.
    ip_header->ip_sum = cksum(ip_header, sizeof(ip_hdr));

    // look up next hop IP in routing table
    RoutingTableEntry next_hop = m_routingTable.lookup(ip_header->ip_dst);
    uint32_t next_hop_address = next_hop.gw; // ip
    const Interface* next_hop_iface = findIfaceByName(next_hop.ifName);

    // look up next hop mac in arp cache
    std::shared_ptr<ArpEntry> arp_lookup_next = m_arp.lookup(next_hop_address);

    // if mac address known in cache, forward as normal
    if (arp_lookup_next != NULL) {
      ethernet_hdr *ip_eth_hdr = (ethernet_hdr*) (ip_packet.data());
      memcpy(ip_eth_hdr->ether_dhost, arp_lookup_next->mac.data(), ETHER_ADDR_LEN); // send to next hop (gw)
      memcpy(ip_eth_hdr->ether_shost, next_hop_iface->addr.data(), ETHER_ADDR_LEN); 
      ip_eth_hdr->ether_type = htons(ethertype_ip);
      sendPacket(ip_packet, next_hop_iface->name);
      std::cerr << "=== Forwarded IP packet to next hop = " << std::endl;
      print_hdrs(ip_packet);
    }

    // not in cache, queue packet and send arp req
    else {
      std::shared_ptr<ArpRequest> req = m_arp.queueArpRequest(next_hop_address, ip_packet, next_hop_iface->name);
    }
  }

  else {
    std::cerr << "Packet is neither ARP or IP. Dropping packet..." << std::endl;
    return;
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
  m_aclLogFile.open("router-acl.log");
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

bool
SimpleRouter::loadACLTable(const std::string& aclConfig)
{
  return m_aclTable.load(aclConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

} // namespace simple_router {
