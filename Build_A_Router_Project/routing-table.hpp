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

#ifndef SIMPLE_ROUTER_ROUTING_TABLE_HPP
#define SIMPLE_ROUTER_ROUTING_TABLE_HPP

#include "core/protocol.hpp"

#include <list>

namespace simple_router {

struct RoutingTableEntry
{
  uint32_t dest;
  uint32_t gw;
  uint32_t mask;
  std::string ifName;
};

/**
 * Routing table of the simple router
 */
class RoutingTable
{
public:
  /**
   * IMPLEMENT THIS METHOD
   *
   * This method should lookup a proper entry in the routing table
   * using "longest-prefix match" algorithm
   *
   * If routing table not found, `throw std::runtime_error("Routing entry not found")`
   */

  int
  incrememt_track_counter(int track_counter) const;

  int 
  increment_move_step(int move_step) const;

  bool
  checkfinishMask(uint32_t shift_mask) const;

  bool
  checklongestPrefix(int prefix, int counter) const;

  bool 
  checkfoundEntry(int offset, int prefix) const;

  bool
  checkMaskBits(int mask_bits, int step_size) const;

  bool
  checkMask(bool end_mask) const;

  RoutingTableEntry
  lookup(uint32_t ip) const;

  bool
  checkEntry(int offset, int prefix) const;

  bool
  load(const std::string& file);

  void
  addEntry(RoutingTableEntry entry);

private:
  std::list<RoutingTableEntry> m_entries;

  friend std::ostream&
  operator<<(std::ostream& os, const RoutingTable& table);
};

std::ostream&
operator<<(std::ostream& os, const RoutingTableEntry& entry);

std::ostream&
operator<<(std::ostream& os, const RoutingTable& table);

} // namespace simple_router

#endif // SIMPLE_ROUTER_ROUTING_TABLE_HPP
