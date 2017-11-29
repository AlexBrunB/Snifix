#include "PacketFactory.hpp"

std::unique_ptr<snfx::Packet> snfx::PacketFactory::makePacket(const uint64_t _protocol, unsigned char *buffer)
{
    struct ethhdr *eth = (struct ethhdr *)(buffer);
    switch(_protocol)
    {
        case    e_protocols::ICMP:
            return (std::make_unique<snfx::ICMP>(buffer));
        case    e_protocols::TCP:
	  return (makeTCPPacket(buffer));
        case    e_protocols::UDP:
            return (std::make_unique<snfx::UDP>(buffer));
        default:
            break;
    }
    switch (ntohs(eth->h_proto))
    {
        case    e_protocols::ARP:
            return (std::make_unique<snfx::ARP>(buffer));
        default:
            return (nullptr);
    }
}

std::unique_ptr<snfx::Packet>	snfx::PacketFactory::makeTCPPacket(unsigned char *buffer)
{
  std::unique_ptr<snfx::TCP>	packet(std::make_unique<snfx::TCP>(buffer));
  std::string			tmp(reinterpret_cast<const char *>(packet->getData() + sizeof (struct ethhdr)
								   + packet->getIphdrlen()
								   + packet->getTcph()->doff * 4));

  
  if (tmp.find("HTTP/") != std::string::npos)
    return (std::make_unique<snfx::HTTP>(buffer));
  else
    return (packet);
}
