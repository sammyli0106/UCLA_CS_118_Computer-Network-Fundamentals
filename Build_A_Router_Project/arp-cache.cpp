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

#define protocol_addr_len 0x04
#define max_num_sent_times 5

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void 
ArpCache::cleanCache()
{
  // Define a iterator to loop through the list of the cache entry 
  std::list<std::shared_ptr<ArpEntry>>::iterator iterator_arp;
  // Define the start and the end position for the looping iterator
  auto iterator_arp_start = m_cacheEntries.begin();
  auto iterator_arp_end = m_cacheEntries.end();

  // Start looping through all the cache entries
  for (iterator_arp = iterator_arp_start; iterator_arp != iterator_arp_end; )
  {
    // Check if the entry pointed by the iterator is valid
    // If not, call the erase function from the m_cacheEntries to remove it
    auto check = (*iterator_arp)->isValid;
    if (!check)
    {
      // Erase the invalid entries
      auto replace = m_cacheEntries.erase(iterator_arp);
      // Update the looping iterator
      iterator_arp = replace;
    }
    else
    {
      // Move on to the next slot
      iterator_arp++;
    }
  }
}

void 
ArpCache::deleteRequest(std::list<std::shared_ptr<ArpRequest>>::iterator iterator)
{
  iterator = m_arpRequests.erase(iterator);
}

time_point 
ArpCache::timeFunc()
{
  // Find the current time by using the ticker function
  return steady_clock::now();
}

std::list<std::shared_ptr<ArpRequest>>::const_iterator
ArpCache::removeArpRequest(std::list<std::shared_ptr<ArpRequest>>::const_iterator arp_iterator)
{   
  return m_arpRequests.erase(arp_iterator);
}

void 
ArpCache::increment(std::list<std::shared_ptr<ArpRequest>>::const_iterator arp_iterator, time_point current_time)
{
  auto time_sent = (*arp_iterator)->timeSent;
  time_sent = current_time;
  auto num_sent_times = (*arp_iterator)->nTimesSent;
  num_sent_times++;
}

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // According to the examples from the functions down below
  // Get the current time for this function
  auto current_time = timeFunc();

  // Define a broadcast address
  uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  // Create a iterator to loop through the arp request
  std::list<std::shared_ptr<ArpRequest>>::const_iterator arp_iterator;
  // This is the start of the iterator 
  auto arp_iterator_start = m_arpRequests.begin();
  // This is the end of the iterator
  auto arp_iterator_end = m_arpRequests.end();

  for (arp_iterator = arp_iterator_start; arp_iterator != arp_iterator_end; )
  {
    // Router does not receive ARP reply after retransmitting an ARP request 5 times
    // Stop transmitting, remove the pending request and any packets
    auto num_of_sent_times = (*arp_iterator)->nTimesSent;
    if (num_of_sent_times >= MAX_SENT_TIME)
    {
      // Remove the arp request pointed by the correpsonding looping iterator 
      arp_iterator = removeArpRequest(arp_iterator);
    }
    else
    {
      // Define the ethernet header size
      auto ethernet_hdr_size = sizeof(ethernet_hdr);
      // Define the arp header size
      auto arp_hdr_size = sizeof(arp_hdr);
      // Create a packet to send out 
      Buffer arp_request_packet(ethernet_hdr_size + arp_hdr_size);

      // Find the interface for the pending packet to send out
      auto name = (*arp_iterator)->packets.front();
      auto interface_name = m_router.findIfaceByName(name.iface);

      // Extract the ethernet header part
      ethernet_hdr* packet_ether_hdr = (ethernet_hdr*) arp_request_packet.data();
      // Define the ethernet type of the ethernet header part
      packet_ether_hdr->ether_type = htons(ethertype_arp);
      auto temp = interface_name->addr.data();
      // Set the source address from the ethernet header address
      memcpy(packet_ether_hdr->ether_shost, temp, ETHER_ADDR_LEN);
      // Set the destination address from the ethernet header address
      memcpy(packet_ether_hdr->ether_dhost, broadcast_addr, ETHER_ADDR_LEN);

      // Extract the arp header part
      arp_hdr* packet_arp_hdr = (arp_hdr*) (arp_request_packet.data() + ethernet_hdr_size);
      // Define the ARP opcode
      packet_arp_hdr->arp_op = htons(arp_op_request);
      // Define the length of protocol address
      packet_arp_hdr->arp_pln = protocol_addr_len;
      // Define the format of the hardware address
      packet_arp_hdr->arp_hrd = htons(arp_hrd_ethernet);
      // Define the length of hardware address
      packet_arp_hdr->arp_hln = ETHER_ADDR_LEN; 
      // Define the format of protocol address to be 0x0800
      packet_arp_hdr->arp_pro = htons(ethertype_ip);
      // Define sender hardware address
      memcpy(packet_arp_hdr->arp_sha, temp, ETHER_ADDR_LEN);

      // Define target IP address
      auto arp_ip_addr = (*arp_iterator)->ip;
      packet_arp_hdr->arp_tip = arp_ip_addr;

      // Define target hardware address
      /// !!!!! Double check the way to use the broadcast address !!!!!!!
      memcpy(packet_arp_hdr->arp_tha, broadcast_addr, ETHER_ADDR_LEN);

      // Define sender IP address to be ip address of the interface
      auto interface_ip = interface_name->ip;
      packet_arp_hdr->arp_sip = interface_ip;

      // Ready to send packet, modify here
      auto iface_name = interface_name->name;
      m_router.sendPacket(arp_request_packet, iface_name);

      // Increment function
      increment(arp_iterator, current_time);

      // Increment the iterator
      arp_iterator++;
    }

    // clean up all the entries
    cleanCache();
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
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
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
