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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  auto cur_time = steady_clock::now();

  // iterate through queued requests
  auto req_itr = m_arpRequests.begin();
  while (req_itr != m_arpRequests.end()) {
    if ((*req_itr)->nTimesSent < MAX_SENT_TIME) {
      // send arp request
      std::string iface_name = (*req_itr)->packets.front().iface;
      const Interface* iface = m_router.findIfaceByName(iface_name);

      // ethernet header
      ethernet_hdr eth_hdr_req;
      memset(eth_hdr_req.ether_dhost, 0xFF, ETHER_ADDR_LEN);
      memcpy(eth_hdr_req.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      eth_hdr_req.ether_type = htons(ethertype_arp);

      // arp header
      arp_hdr arp_hdr_req;
      arp_hdr_req.arp_hrd = htons(arp_hrd_ethernet);
      arp_hdr_req.arp_pro = htons(ethertype_ip);
      arp_hdr_req.arp_hln = ETHER_ADDR_LEN;
      arp_hdr_req.arp_pln = 4; // given in spec that IPv4 has 4-octet adresse 0x04
      arp_hdr_req.arp_op = htons(arp_op_request);
      memcpy(arp_hdr_req.arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      arp_hdr_req.arp_sip = iface->ip;
      memset(arp_hdr_req.arp_tha, 0xFF, ETHER_ADDR_LEN);
      arp_hdr_req.arp_tip = (*req_itr)->ip;

      // buffer to send packet
      Buffer packet(sizeof(ethernet_hdr)+sizeof(arp_hdr));
      memcpy(packet.data(), &eth_hdr_req, sizeof(ethernet_hdr));
      memcpy(packet.data() + sizeof(ethernet_hdr), &arp_hdr_req, sizeof(arp_hdr));
      m_router.sendPacket(packet, iface_name);
      std::cerr << "Sent an ARP Request" << std::endl;

      // update current request and itr
      (*req_itr)->timeSent = cur_time;
      (*req_itr)->nTimesSent++;
      req_itr++;
    }
    else {
      req_itr = m_arpRequests.erase(req_itr);
    }
  }

  // remove invalid cache entries
  auto cache_itr = m_cacheEntries.begin();
  while (cache_itr != m_cacheEntries.end()) {
    if ((*cache_itr)->isValid) {
      cache_itr++;
    }
    else {
      cache_itr = m_cacheEntries.erase(cache_itr);
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueArpRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeArpRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
