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

#include "routing-table.hpp"
#include "core/utils.hpp"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#define neg_one -1
#define offset_eight 8

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

bool
RoutingTable::checkfinishMask(uint32_t shift_mask) const
{
  bool answer = false;
  if (shift_mask == 0)
  {
    // Set end of mask to be true
    answer = true;
  }
  return answer;
}
    
bool
RoutingTable::checklongestPrefix(int prefix, int counter) const
{
	bool answer = false;

	if (prefix < counter)
	{
		answer = true;
	}

	return answer;
}    

bool 
RoutingTable::checkfoundEntry(int offset, int prefix) const
{
	bool answer = false;
	if (offset < prefix)
	{
		answer = true;
	}

	return answer;
}

bool
RoutingTable::checkMaskBits(int mask_bits, int step_size) const
{
	bool answer = false;
	if (mask_bits > step_size)
	{
		answer = true;
	}

	return answer;
}

bool
RoutingTable::checkMask(bool end_mask) const
{
	bool answer = false;

	if (end_mask == false)
	{
		answer = true;
	}

	return answer;
}
  
int
RoutingTable::incrememt_track_counter(int track_counter) const
{
	int answer = track_counter;
	answer++;
  	return answer;
}

int 
RoutingTable::increment_move_step(int move_step) const
{
	int answer = move_step;
	answer++;
  	return answer;
}

bool
RoutingTable::checkEntry(int offset, int prefix) const
{
	bool answer = false;
	if (checkfoundEntry(offset, prefix))
  	{
    	// Return the found entry if answer is true
    	answer = true;
  	}

  	return answer;
}

RoutingTableEntry
RoutingTable::lookup(uint32_t ip) const
{
  // FILL THIS IN

  // The method should lookup a proper entry in the routing table
  // using the "longest-prefix match" algorithm

  // Loop through the routing table entries 
  // Create a routing table list iterator 
  std::list<RoutingTableEntry>::const_iterator table_iterator;
  auto table_iterator_start = m_entries.begin();
  auto table_iterator_end = m_entries.end();

  // Global variables
  int longest_prefix = neg_one;
  // Create a table entry to return at the end of func
  RoutingTableEntry foundEntry;

  for (table_iterator = table_iterator_start; table_iterator != table_iterator_end; table_iterator++)
  {
    // Check whether the prefix of our current entry is the same as ip
    // Find the gw and mask of the current
    uint32_t current_gw = table_iterator->gw;
    uint32_t current_mask = table_iterator->mask;

    // Define the variables for comparison
    auto temp_1 = (current_mask & ip);
    auto temp_2 = (current_mask & current_gw);

    if (temp_1 == temp_2)
    {
      // Set up a flag whether it is finish or not
      bool finish_mask = false;
      // Get the current mask
      auto current_mask = table_iterator->mask;
      // Find the length of the current mask
      auto mask_size = sizeof(current_mask);
      // Find the total bits of the entire mask
      int total_bits = mask_size * offset_eight;
      int calc_mask_bits = total_bits;
      // Set up variables for moving forward along the prefix during comparision
      int move_step = 0;
      int track_counter = neg_one;

      while(checkMaskBits(calc_mask_bits, move_step) && checkMask(finish_mask))
      {
        // incrememt the counter
        int count_1 = track_counter;
        track_counter = incrememt_track_counter(count_1);

        // Convert the order of the bytes to prepare for shifting
        auto converted_byte = htonl(current_mask);
        auto shift_mask = converted_byte << move_step;
        // There is nothing left
        finish_mask = checkfinishMask(shift_mask);
        
        // increment the move step
        int count_2 = move_step;
        move_step = increment_move_step(count_2);
      }

      // Check the track_counter and the longest_prefix
      if (checklongestPrefix(longest_prefix, track_counter))
      {
        // Set the longest prefix to the counter that I am keeping track of 
        auto iterator_content = *table_iterator;
        foundEntry = iterator_content;
        longest_prefix = track_counter;
      }
    }
  }

  // Check the found entry to see if it is the longest prefix that we are looking for 
  if (checkEntry(neg_one, longest_prefix) == true)
  {
  	return foundEntry;
  }

  throw std::runtime_error("Routing entry not found");
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

bool
RoutingTable::load(const std::string& file)
{
  FILE* fp;
  char  line[BUFSIZ];
  char  dest[32];
  char  gw[32];
  char  mask[32];
  char  iface[32];
  struct in_addr dest_addr;
  struct in_addr gw_addr;
  struct in_addr mask_addr;

  if (access(file.c_str(), R_OK) != 0) {
    perror("access");
    return false;
  }

  fp = fopen(file.c_str(), "r");

  while (fgets(line, BUFSIZ, fp) != 0) {
    sscanf(line,"%s %s %s %s", dest, gw, mask, iface);
    if (inet_aton(dest, &dest_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              dest);
      return false;
    }
    if (inet_aton(gw, &gw_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              gw);
      return false;
    }
    if (inet_aton(mask, &mask_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              mask);
      return false;
    }

    addEntry({dest_addr.s_addr, gw_addr.s_addr, mask_addr.s_addr, iface});
  }
  return true;
}

void
RoutingTable::addEntry(RoutingTableEntry entry)
{
  m_entries.push_back(std::move(entry));
}

std::ostream&
operator<<(std::ostream& os, const RoutingTableEntry& entry)
{
  os << ipToString(entry.dest) << "\t\t"
     << ipToString(entry.gw) << "\t"
     << ipToString(entry.mask) << "\t"
     << entry.ifName;
  return os;
}

std::ostream&
operator<<(std::ostream& os, const RoutingTable& table)
{
  os << "Destination\tGateway\t\tMask\tIface\n";
  for (const auto& entry : table.m_entries) {
    os << entry << "\n";
  }
  return os;
}

} // namespace simple_router
