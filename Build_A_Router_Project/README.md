Name: Sum Yi Li
UID: 505146702

High leve design of the implementation:

Simple router.cpp: 
1. First, I parse the received packet's ethernet header address
2. I extract the ethernet type of the ethernet header address 
3. I check to see if it is ARP packet or IP packet
4. If it is an ARP packet, I need to extract the ARP header address
5. I check the opcode to see whether it is an ARP request or an ARP reply
6. If it is an ARP request, then I create an ARP reply packet 
7. For the ARP reply packet, replace the ethernet header destinaton address with the incoming packet's ethernet header source address
8. For the ARP reply packet, replace the ethernet header source address with the incoming packet's ethernet header destination address
9. At last, modify the rest of the corresponding fields and sent out at the correct interface (given as parameter of the function)
10. If it is an ARP reply packet, then we need to extract the IP and MAC address information and store in the ARP cache by using the insertArpEntry function
11. Then, I create a loop to go through all the pending packets in the cache and send all the pending packets out correspondingly. 
12. Before I send the pending packets, I need to recalculate a new checksum for each of the new pending packets.
13. If it is an IP packet, then I need to first verify the checksum and the length of the incoming packet by using the cksum function
14. I extract the destination IP to check whether it is destined to the router or not
15. If it is destined to the router, I need to check if it is an ICMP packet by checking whether the protocol is equal to one or not.
    If it is ICMP packet, then I need to check if it is an icmp echo request packet. If it is not, then I simply discard the packet and do nothing.
    If it is an ICMP echo reply packet, then I need to verify the checksum for both the ethernet and ip header part and 
    prepare the ICMP echo reply packet by filling in the correct values of the fields. 
    One thing to be aware that we need to append all the ICMP data to the reply packet which is possible to be larger than icmp header size.
    Then, we send the ICMP echo reply packet out at the interface which is given as parameter
16. If it is not destined to the router, then I need to forward the packet by finding the next hop IP address from the routing table. I need to extract the correct interface
    name and look up the ARP cache to check if the corrresponding MAC address has already
    been mapped to the IP destination address. 
17. If I am able to find a valid entry from the routing table, then I forward the packet to the corresponding destination
18. If I am unable to find a valid entry from the routing table, then I will cache the packet and then 
    send a ARP request

arp-cache.cpp:
1. I create an iterator to loop through all the arp request in the arp cache. If the router does not receive the arp reply after transmitting an ARP request 5 times, I will stop transmitting and simply remove the pending request and any packets relate to it. 
    If this is not the case, I should prepare a ARP request packet and send about once a second
    until an ARP reply comes back or the request has been send out at least 5 times.
    At last, I need to remove all the packets that are queued for the transmission that are 
    associated with the request. I need to clean up all the invalid entries by using one of
    implemented function

routing-table.cpp:
1.  In my implementation, I first loop through the routing table entry and then I get the
    gw and mask of the entry. Then, I set up a boolean flag to indicate the end of the mask
    and some counter to keep track of the steps I am currently in. The while will keep running
    when the calculated mask bits is bigger than my move_step and also when it is not the end
    of mask. Within the loop, I will update the counter and check whether it is the end of
    maks yet. After the loop, if my longest_prefix is less than my track_counter, then I will
    update my foundEntry to my current iterator and the longest prefix to the compared counter.
    Outside of both of the loops, if my longest_prefix is still greater than negative one, 
    which means I find the entry and this is my longest prefix. 


Problems that I ran into and how to solve it:

First, I am not able to ping from the client to any app servers. Then, I find out it is 
relate to the ICMP packet part. The error that I making is I do not become aware of the 
fact that ICMP section contains the payload data and the length of the entire ICMP 
section could be longer than ICMP header address. There, I have use the wrong length to 
calculate my checksum. After I handle the ethernet, ip and icmp header address part, I 
forget to attach the entire icmp payload data to the icmp echo reply packet. After, I fix
the two errors, I am able to ping from client to app servers.

Second, I have encountered the error of having 3.file's output file size is always 5.
Then, I trace my code in the arp-cache.ccp, the error is related to the way I erase the
invalid entries in the arp cache. I am using erase function to remove the entry. But, the
erase function will automatically point to the next entry already and I already have
a ++iterator. So the problem is I am moving two entries ahead all the time and skipping entry.
The I solve it by moving the ++iterator into a if else statement. If the there is invalid
entry, then I will call the erase function without incrementing the iterator, else
I will increment the iterator by one. 

Sources:

1. https://thispointer.com/different-ways-to-iterate-over-a-set-in-c/
2. https://linux.die.net/man/3/htons
3. https://www.geeksforgeeks.org/constants-in-c-cpp/
4. http://www.cplusplus.com/doc/tutorial/operators/
5. http://www.cplusplus.com/forum/beginner/218111/
6. https://stackoverflow.com/questions/15185801/cout-was-not-declared-in-this-scope
7. https://stackoverflow.com/questions/35596896/invalid-conversion-from-long-int-to-void-fpermissive
8. https://www.includehelp.com/tips/c/how-to-initialize-array-elements-with-hexadecimal-values-in-c.aspx
