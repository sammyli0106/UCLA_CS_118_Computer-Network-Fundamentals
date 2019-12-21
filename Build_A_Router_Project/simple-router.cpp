/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
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
#include <iostream>
#include <string>

using namespace std;

#define ETHER_PROTO_ADDR 0X04
#define ICMP_ETHER_HOST_LEN 0x00

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
bool 
SimpleRouter::toRouter(ip_hdr* my_ip_hdr)
{
  bool answer = false;
  auto my_ip_dst = my_ip_hdr->ip_dst;
  auto ip_destination = my_ip_dst;
  for (auto elem : m_ifaces)
  {
    // IP packet is destined to the router
    auto my_ip = elem.ip; 
    if (my_ip == ip_destination)
    {
      answer = true;
    }
  }
  return answer;
}

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  // Ignore the received packet of the interface is unknown 
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  // Extract the packet content (buf = packet content)
  const uint8_t* buf = packet.data();
  uint32_t buf_length = packet.size();

  //Print out the received packet's header to check
  std::cerr << "Header of the received packet:\n";
  print_hdrs(buf, buf_length);

  // 2. Extract the ethernet header from the received packet

  // Create a broadcast address
  uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xFF, 0XFF, 0XFF, 0xFF, 0xFF, 0xFF};

  const ethernet_hdr* my_ether_hdr = (const ethernet_hdr*) packet.data();

  // Get the ether_type of the received packet
  auto ethtype = my_ether_hdr->ether_type;
  // Use htons to convert from host byte order to network byte order
  auto ip_type = htons(ethertype_ip);
  auto arp_type = htons(ethertype_arp);

  // 3. Check the type of the packet
  if (ethtype == arp_type)
  {
    // This is an ARP packet
    std::cerr << "Received packet is a ARP packet\n";
    // Extract the arp header address by casting and move over the pointer
    auto min_length = sizeof(ethernet_hdr);
    const arp_hdr* my_arp_hdr = (const arp_hdr*) (min_length + packet.data());

    // Get the opcode from my arp address
    auto my_arp_opcode = my_arp_hdr->arp_op;
    // Use htons
    auto arp_request = htons(arp_op_request);
    auto arp_reply = htons(arp_op_reply);

    // 3.1 ARP request -> send ARP reply
    if (my_arp_opcode == arp_request)
    {
      // This is a ARP request
      std::cerr << "Received packet is a ARP request\n";
      
      // Build the ARP reply packet
      auto ethernet_hdr_size = sizeof(ethernet_hdr);
      auto arp_hdr_size = sizeof(arp_hdr);
      auto arp_reply_packet_size = ethernet_hdr_size + arp_hdr_size;
      // Use the Buffer initalize type for the reply packet
      Buffer arp_response_packet(arp_reply_packet_size);

      // Define the ethernet header from the arp reply packet
      auto reply_packet_data = arp_response_packet.data();
      ethernet_hdr* arp_resp_packet_ether_hdr = (ethernet_hdr*) reply_packet_data;

      // Define the ethernet type of arp response packet
      arp_resp_packet_ether_hdr->ether_type = htons(ethertype_arp);
      // Find out all the needed host from our packet and arp packet
      auto my_packet_shost = my_ether_hdr->ether_shost;
      auto arp_packet_dhost = arp_resp_packet_ether_hdr->ether_dhost;
      auto arp_packet_shost = arp_resp_packet_ether_hdr->ether_shost;
      auto router_address = iface->addr.data();
      // Define the source address = router's address
      memcpy(arp_packet_dhost, my_packet_shost, ETHER_ADDR_LEN);
      // Define the packet destination address = sender of the ARP request
      // Destination first, source second
      memcpy(arp_packet_shost, router_address, ETHER_ADDR_LEN);

      // This is the ARP header section
      // Define arp header from the arp reply packet
      arp_hdr* arp_resp_packet_arp_hdr = (arp_hdr*) (arp_response_packet.data() + ethernet_hdr_size);
      // Define arp packet format of hardware address = ethernet hardware address
      arp_resp_packet_arp_hdr->arp_hrd = htons(arp_hrd_ethernet);
      // Define arp packet format of protocol address = ethernet protocol address (ethertype_ip = 0x0800)
      arp_resp_packet_arp_hdr->arp_pro = htons(ethertype_ip);
      // Define arp packet length of hardware address = ethernet address length
      arp_resp_packet_arp_hdr->arp_hln = ETHER_ADDR_LEN;
      // Define arp packet length of protocol address = ethernet protocol address length
      arp_resp_packet_arp_hdr->arp_pln = ETHER_PROTO_ADDR;
      // Define arp packet arp opcode = arp reply opcode
      arp_resp_packet_arp_hdr->arp_op = htons(arp_op_reply);
      // Define sender hardware address = router address
      memcpy(arp_resp_packet_arp_hdr->arp_sha, router_address, ETHER_ADDR_LEN);
      // Define sender IP address = ARP request's target IP address
      arp_resp_packet_arp_hdr->arp_sip = my_arp_hdr->arp_tip;
      // Define the target hardware address = ARP requester hardware address
      memcpy(arp_resp_packet_arp_hdr->arp_tha, my_arp_hdr->arp_sha, ETHER_ADDR_LEN);
      // Define the target IP address = ARP requester hardware address
      arp_resp_packet_arp_hdr->arp_tip = my_arp_hdr->arp_sip;

      // Finish building the ARP reply packet
      std::cerr << "This is our ARP reply packet:\n";
      // Double check the ARP packet content and length by printing it out
      print_hdrs(arp_response_packet.data(), arp_hdr_size + ethernet_hdr_size);

      // Put it in function later to send the ARP response packet
      sendPacket(arp_response_packet, inIface);
    }
    // 3.2 ARP reply -> store IP/MAC info, send cached packets out
    else if (my_arp_opcode == arp_reply)
    {
      // This is a ARP reply
      std::cerr << "Received packet is a ARP response packet\n";

      // Create a buffer
      Buffer reply_mac_addr(ETHER_ADDR_LEN);
      // Copy the sender hardware address data part into the reply_mac_addr part
      auto reply_mac_data = reply_mac_addr.data();
      auto my_arp_sha = my_arp_hdr->arp_sha;
      memcpy(reply_mac_data, my_arp_sha, ETHER_ADDR_LEN);
      // Find out the IP address from our ARP header (sender IP address)
      // auto my_arp_sip = my_arp_hdr->arp_sip;
      // uint32_t reply_mac_ip_addr = my_arp_sip;

      // If we know the sneder IP address, get the ARP request
      // Then insert the IP/MAC info inside the ARP cache by the insertArpEntry
      std::shared_ptr<ArpRequest> arp_packet_request = nullptr;
      // arp_packet_request = m_arp.insertArpEntry(reply_mac_addr, reply_mac_ip_addr);
      arp_packet_request = m_arp.insertArpEntry(reply_mac_addr, my_arp_hdr->arp_sip);

      // Check if the arp request shows up as nullptr
      if (arp_packet_request != nullptr)
      {
        // Prepare to loop through all the pending packets in the ARP cache and send the pending packets
        // Create a looping iterator
        std::list<PendingPacket>::const_iterator iterator;
        auto begin = arp_packet_request->packets.begin();
        auto end = arp_packet_request->packets.end();

        for (iterator = begin; iterator != end; iterator++)
        {
          auto packet_data = (iterator->packet).data();

          // Change the pending packet ethernet header before forwarding
          // ethernet_hdr* ether_hdr_forward = (ethernet_hdr*) ((iterator->packet).data());
          ethernet_hdr* ether_hdr_forward = (ethernet_hdr*) (packet_data);

          auto ether_dest = ether_hdr_forward->ether_dhost;
          auto ether_source = ether_hdr_forward->ether_shost;
          auto my_arp_sha = my_arp_hdr->arp_sha;

          // Define the source address = interface address where the packet coming out
          memcpy(ether_source, (findIfaceByName(iterator->iface)->addr).data(), ETHER_ADDR_LEN);
          // Define the destination address = arp response hardware address
          memcpy(ether_dest, my_arp_sha, ETHER_ADDR_LEN);

          auto ethernet_hdr_size = sizeof(ethernet_hdr);
          auto ip_hdr_size = sizeof(ip_hdr);

          // Recalculate the checksum
          ip_hdr* ip_hdr_forward = (ip_hdr*) (packet_data + ethernet_hdr_size);
          // ip_hdr* ip_hdr_forward = (ip_hdr*) ((iterator->packet).data() + ethernet_hdr_size);
          // Decrement the TTL by 1
          ip_hdr_forward->ip_ttl--;
          // Reset the sum to zero before recalculation
          ip_hdr_forward->ip_sum = 0;
          // Recalculate the sum first
          ip_hdr_forward->ip_sum = cksum(ip_hdr_forward, ip_hdr_size);

          // Double check before sending the pending packet out
          std::cerr << "These are the pending packets that need to be forwarded:\n";
          // Print the conten from the pending packets before sending out
          // print_hdrs(iterator->packet.data(), ethernet_hdr_size + ip_hdr_size);

          // Ready to send the packet now
          auto packet = iterator->packet;
          auto out_interface = iterator->iface;
          sendPacket(packet, out_interface);
        }

        // Outside the for loop, clean up all the request after sending all the pending packets
        m_arp.removeRequest(arp_packet_request);
      }
    }
  }
  // This is an IP packet
  else if (ethtype == ip_type)
  {
    // This is a IP packet
    std::cerr << "Received packet is an IP packet\n";

    // Extract the ip header address by casting and move over the pointer
    auto ethernet_hdr_size = sizeof(ethernet_hdr);
    auto ip_hdr_size = sizeof(ip_hdr);
    ip_hdr* my_ip_hdr = (ip_hdr*) (ethernet_hdr_size + packet.data());

    auto my_ip_len = my_ip_hdr->ip_len;

    // First, verify the length of the header
    // The minimum length of the packet is just the packet without any data
    if (my_ip_len < ip_hdr_size)
    {
      std::cerr << "The IP header has a bad verified length\n";
      return;
    }
    else 
    {
      // Make a copy of the IP header for the checksum calculation
      Buffer buffer_copy_ip_hdr(ip_hdr_size);
      // Move the IP header address into the IP header address field in our copy
      auto buffer_data = buffer_copy_ip_hdr.data();
      memcpy(buffer_data, my_ip_hdr, ip_hdr_size);

      // Get the actual copy of the IP header by casting the correct type
      ip_hdr* copy_ip_hdr = (ip_hdr*) (buffer_data);
      // Find out the checksum and verify it
      // Reset our copy of checksum to zero first
      copy_ip_hdr->ip_sum = 0;
      // Extract the received checksum
      auto my_ip_sum = my_ip_hdr->ip_sum;
      uint16_t received_sum = my_ip_sum;
      // Extract the calculated checksum by using the cksum function
      uint16_t calculated_sum = cksum(copy_ip_hdr, ip_hdr_size);

      // Check the checksum
      if (received_sum == calculated_sum)
      {
        // Check if the IP packet is destined to the router
        // Set up a bool flag
        bool deliver_to_router = toRouter(my_ip_hdr);

        // IP packet is destined to the router
        if (deliver_to_router == true)
        {
          // If it is ICMP packet
          // Check against the protocol type to see if it is ICMP packet
          if (my_ip_hdr->ip_p == 1)
          {
            // This is a ICMP packet 
            std::cerr << "Received packet is a ICMP packet\n";

            auto ethernet_hdr_size = sizeof(ethernet_hdr);
            auto ip_hdr_size = sizeof(ip_hdr);
            auto packet_size = packet.size();
            auto packet_data = packet.data();

            // Extract the ICMP header
            icmp_hdr* my_icmp_hdr = (icmp_hdr*) (packet_data + ethernet_hdr_size + ip_hdr_size);

            auto my_icmp_type = my_icmp_hdr->icmp_type;

            // This is not a icmp echo request packet
            if (my_icmp_type != 8)
            {
              // Print a hinted message
              std::cerr << "Received packet is not a ICMP echo request packet\n";
              return;
            }

            // Redo the ICMP checksum
            Buffer buffer_copy_icmp_hdr(packet_size - ethernet_hdr_size - ip_hdr_size);

            // Get the buffer data
            auto buffer_copy_data = buffer_copy_icmp_hdr.data();

            // Copy the icmp buffer data
            memcpy(buffer_copy_data, my_icmp_hdr, packet_size - ethernet_hdr_size - ip_hdr_size);
            icmp_hdr* copy_icmp_hdr = (icmp_hdr*) (buffer_copy_data);

            // Compute the checksum section
            copy_icmp_hdr->icmp_sum = 0;

            auto my_icmp_sum = my_icmp_hdr->icmp_sum; 

            auto icmp_received_cksum = my_icmp_sum;
            auto icmp_calculated_cksum = cksum(copy_icmp_hdr, packet_size - ethernet_hdr_size - ip_hdr_size);

            if (icmp_received_cksum != icmp_calculated_cksum)
            {
              // The checksum is not good, send a warning message
              std::cerr << "The ICMP checksum is not good\n";
              return;
            }

            // Send ICMP echo reply, provide the source and ip_hdr, create a function to do this
            std::cerr << "Prepare to send a echo reply\n";
            // Find the length and create the buffer packet (solve seg fault here)
            Buffer icmp_buffer(packet_size);

            auto icmp_buffer_data = icmp_buffer.data();

            // Extract the ethernet header address from the icmp buffer
            ethernet_hdr* ether_hdr_icmp = (ethernet_hdr*) (icmp_buffer_data); 

            auto icmp_buffer_source = ether_hdr_icmp->ether_shost;
            auto icmp_buffer_dst = ether_hdr_icmp->ether_dhost;

            // Set icmp source ethernet address to be each interface's addr.data()
            memcpy(icmp_buffer_source, iface->addr.data(), ETHER_ADDR_LEN);
            // Set icmp destination ethernet address to be source of the orginal packet
            memcpy(icmp_buffer_dst, my_ether_hdr->ether_shost, ETHER_ADDR_LEN);
            // Set the icmp packet ethernet header address to ip ethertype
            ether_hdr_icmp->ether_type = htons(ethertype_ip);

            // Extract the ip header address from the icmp buffer
            ip_hdr* ip_hdr_icmp = (ip_hdr*) (ethernet_hdr_size + icmp_buffer_data);
            // copy the my_ip_hdr into the icmp ip header address (segfault happen here)
            memcpy(ip_hdr_icmp, my_ip_hdr, ip_hdr_size);

            ip_hdr_icmp->ip_tos = 0;
            // ip_off to be htons(IP_DF)
            ip_hdr_icmp->ip_off = htons(IP_DF);
            // ip_id to be zero
            ip_hdr_icmp->ip_id = 0;
            // Set the ip_ttl to 64 from the icmp buffer
            ip_hdr_icmp->ip_ttl = 64;
            // Set the ip_sum to zero from the icmp buffer
            ip_hdr_icmp->ip_sum = 0;
            // Set the icmp buffer ip_src to ip_dst from my_ip_hdr
            ip_hdr_icmp->ip_src = my_ip_hdr->ip_dst;
            // Set the icmp buffer ip_dst to ip_src from my_ip_hdr
            ip_hdr_icmp->ip_dst = my_ip_hdr->ip_src;
            // Recalculate the checksum from the icmp buffer
            auto ip_calc_cksum_icmp = cksum(ip_hdr_icmp, ip_hdr_size);
            ip_hdr_icmp->ip_sum = ip_calc_cksum_icmp;

            // Prepare the ICMP reply packet
            icmp_hdr* icmp_reply_hdr = (icmp_hdr*) (icmp_buffer_data + ethernet_hdr_size + ip_hdr_size);
            //copy the my_icmp_hdr into the icmp header address
            memcpy(icmp_reply_hdr, my_icmp_hdr, packet_size - ethernet_hdr_size - ip_hdr_size);

            // Set icmp_code to zero
            icmp_reply_hdr->icmp_code = 0;
            // Set icmp_sum to zero
            icmp_reply_hdr->icmp_sum = 0;
            // Set icmp_type to zero
            icmp_reply_hdr->icmp_type = 0;
            // Update the icmp_sum
            auto icmp_reply_cksum = cksum(icmp_reply_hdr, packet_size - ethernet_hdr_size - ip_hdr_size);
            icmp_reply_hdr->icmp_sum = icmp_reply_cksum;

            std::cerr << "This is our ICMP echo reply packet\n";

            //Print the received packet
            print_hdrs(packet_data, packet_size);

            // Double check the ARP packet content and length by printing it out
            print_hdrs(icmp_buffer_data, packet_size);

            // Put it in function later to send the icmp echo reply packet
            sendPacket(icmp_buffer, inIface);
            // Just send the ARP response packet
            std::cerr << "Just call sendPacket() and send the ICMP echo reply packet\n";
          }
          else 
          {
            // Discard the packet, not ICMP packet
            std::cerr << "Received Packet is not an ICMP packet\n";
            return;
          }
        }
        // IP packet is not destined to the router
        else if (deliver_to_router == false)
        {
          // The packet is not destined to the router
          std::cerr << "The received packet is not destined to the router\n";

          // 4. Forward the packets 

          // 4.1 Look up the routing table and find the next hop
          auto my_ip_dst = my_ip_hdr->ip_dst;
          RoutingTableEntry next_entry = m_routingTable.lookup(my_ip_dst);

          // 4.2 Look up ARP cache
          // Look up the ARP cache to check whether MAC address correspond to IP destination address
          auto my_entry_gw = next_entry.gw;
          std::shared_ptr<ArpEntry> arp_entry = m_arp.lookup(my_entry_gw);

          // Find the next entry interface name
          auto my_ifName = next_entry.ifName;
          std::string next_entry_interface_name = my_ifName;

          // Define all the ethernet header address sizes
          auto ethernet_hdr_size = sizeof(ethernet_hdr);
          auto ip_hdr_size = sizeof(ip_hdr);
          auto arp_hdr_size = sizeof(arp_hdr);

          // If ARP entry found, forward the packet
          if (arp_entry != nullptr)
          {
            // Forwarding message
            std::cerr << "Start forwarding packets that are not mine...\n";
            // Prepare the fowarding packet by using the original packet
            // All the fields stay the same and change the corresponding fields
            Buffer forwarding_packet = packet;

            // Extract the ethernet header address from the forwarding packet
            // We need it to modify ethernet source and destination address
            auto forwarding_data = forwarding_packet.data();
            ethernet_hdr* forwarding_packet_ethernet_addr = (ethernet_hdr*) forwarding_data;

            // Get the ethernet source host and the destination host
            auto forwarding_packet_source = forwarding_packet_ethernet_addr->ether_shost;
            auto forwarding_packet_dst = forwarding_packet_ethernet_addr->ether_dhost;

            // modify the ether_type of the fowarding packet ethernet address
            forwarding_packet_ethernet_addr->ether_type = htons(ethertype_ip);
            // Define the ethernet source address
            // Extract the address of the founded interface
            auto interface_addr = (findIfaceByName(next_entry_interface_name)->addr).data();
            memcpy(forwarding_packet_source, interface_addr, ETHER_ADDR_LEN);
            // Define the ethernet destination address
            auto arp_data = (arp_entry->mac).data();
            memcpy(forwarding_packet_dst, arp_data, ETHER_ADDR_LEN);

            auto forwarding_packet_data = forwarding_packet.data();

            // 4.2 Update the IP header, TTL and checksum
            // Extract the ip heade address first 
            ip_hdr* forwarding_packet_ip_hdr = (ip_hdr*) (ethernet_hdr_size + forwarding_packet_data);
            // Calculate the checksum again
            // Decrease TTL by 1
            forwarding_packet_ip_hdr->ip_sum = 0;
            forwarding_packet_ip_hdr->ip_ttl--;
            forwarding_packet_ip_hdr->ip_sum = cksum(forwarding_packet_ip_hdr, ip_hdr_size);

            // Check the forwarding packet information
            std::cerr << "This is the forwarding packet that is not destined to the router";
            // Print the stuffs inside
            auto total_length = ip_hdr_size + ethernet_hdr_size;
            print_hdrs(forwarding_packet_data, total_length);

            // Ready to send the packet
            sendPacket(forwarding_packet, (findIfaceByName(next_entry_interface_name))->name);
            // sendPacket(forwarding_packet, next_entry_interface_name);
            std::cerr << "Just call sendPacket() and send forwarding packet";

          }
          // If ARP entry not found, cache the packet and send ARP request
          else
          {
            // Put a starting message
            std::cerr << "Put packets in the queue and start to create arp request...";

            // Find length of the arp_request packet
            auto arp_request_length = arp_hdr_size + ethernet_hdr_size;

            // Initialize the ARP request packet 
            Buffer arp_request(arp_request_length);

            // Put the received packet in the queue
            auto next_gw = next_entry.gw;
            auto next_interface_name = next_entry.ifName;
            m_arp.queueRequest(next_gw, packet, next_interface_name);

            // Extract the ethernet header address
            ethernet_hdr* request_ether_hdr = (ethernet_hdr*) arp_request.data();

            // Extract the arp header
            arp_hdr* request_arp_hdr = (arp_hdr*) (ethernet_hdr_size + arp_request.data());

            // Set ether_type to ether_type of arp
            request_ether_hdr->ether_type = htons(ethertype_arp);

            // Find the ethernet header source and destination of the request arp packet
            auto request_source = request_ether_hdr->ether_shost;
            auto request_dst = request_ether_hdr->ether_dhost;

            // Set source to be the data from the corresponding interface 
            auto next_entry_data = (findIfaceByName(next_entry_interface_name)->addr).data();
            memcpy(request_source, next_entry_data, ETHER_ADDR_LEN);

            // Set destination to be the broadcast address
            // !!! Be aware of the form of the broadcast address !!!!!
            memcpy(request_dst, broadcast_addr, ETHER_ADDR_LEN);

            // Define the length of hardware addresss to be ethernet address length
            request_arp_hdr->arp_hln = ETHER_ADDR_LEN; 

            // Define the ARP code (command) to be opcode of arp request
            request_arp_hdr->arp_op = htons(arp_op_request);

            // Define the format of protocol address
            request_arp_hdr->arp_pro = htons(ethertype_ip);

            // Define the format of hardware address to be arp hardware format
            request_arp_hdr->arp_hrd = htons(arp_hrd_ethernet);

            // Define the length of protocol address
            request_arp_hdr->arp_pln = ETHER_PROTO_ADDR;

            // Define the sender hardware address to be interface data
            memcpy(request_arp_hdr->arp_sha, next_entry_data, ETHER_ADDR_LEN);

            // Define the target hardware address to be broadcast address
            // Beware of the broadcast address
            memcpy(request_arp_hdr->arp_tha, broadcast_addr, ETHER_ADDR_LEN);

            // Define the target IP address to be destination ip of the ip header address
            auto my_request_ip_dst = my_ip_hdr->ip_dst;
            request_arp_hdr->arp_tip = my_request_ip_dst;

            // Define the sender IP address to be interface ip address
            auto interface_ip_addr = findIfaceByName(next_entry_interface_name)->ip;
            request_arp_hdr->arp_sip = interface_ip_addr;

            // We are ready to send out the arp request packet
            sendPacket(arp_request, (findIfaceByName(next_entry_interface_name))->name);
          }
        }
      }
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
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
}

// namespace simple_router {
