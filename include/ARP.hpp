#ifndef     __ARP_HPP__
# define    __ARP_HPP__

# include   <string>
# include   <net/if_arp.h>
# include   "Packet.hpp"

namespace   snfx
{
    class   ARP : public Packet
    {
        public:
                    ARP();
                    ARP(unsigned char *_data);
            virtual ~ARP() {};
            struct arphdr   *getArph() const;
            std::string     &getProtocol();
            uint64_t        getHardwareType() const;
            uint64_t        getProtocolType() const;
            uint64_t        getHardwareLength() const;
            uint64_t        getProtocolLength() const;
            uint64_t        getARPcode() const;
        private:
            struct arphdr   *arph;
            std::string     protocol;
            uint64_t        hw_type;
            uint64_t        proto_type;
            uint64_t        hw_length;
            uint64_t        proto_length;
            uint64_t        opcode;
    };
};

#endif      //__ARP_HPP__