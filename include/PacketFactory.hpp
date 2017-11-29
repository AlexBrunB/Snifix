#ifndef     __PACKETFACTORY_HPP__
# define    __PACKETFACTORY_HPP__

# include   <memory>
# include   <netinet/if_ether.h>
# include   "Packet.hpp"
# include   "ARP.hpp"
# include   "ICMP.hpp"
# include   "TCP.hpp"
# include   "UDP.hpp"
# include   "HTTP.hpp"

namespace   snfx
{
    class   PacketFactory
    {
        public:
            static std::unique_ptr<Packet>  makePacket(const uint64_t protocol, unsigned char *buffer);
        private:
            enum    e_protocols
            {
                    ICMP    = 1,
                    TCP     = 6,
                    UDP     = 17,
                    ARP     = ETH_P_ARP
            };
	    static std::unique_ptr<snfx::Packet>  makeTCPPacket(unsigned char *buffer);
    };
}

#endif      //__PACKETFACTORY_HPP__
