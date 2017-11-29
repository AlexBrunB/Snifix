#include    "ARP.hpp"

snfx::ARP::ARP(unsigned char *_data) : Packet(_data),
    arph((struct arphdr *)(_data + iphdrlen + sizeof(struct ethhdr))),
    protocol("ARP"),
    hw_type(arph->ar_hrd),
    proto_type(arph->ar_pro),
    hw_length(arph->ar_hln),
    proto_length(arph->ar_pln),
    opcode(arph->ar_op)
{
}

struct arphdr   *snfx::ARP::getArph() const
{
    return (this->arph);
}

std::string     &snfx::ARP::getProtocol()
{
    return (this->protocol);
}

uint64_t        snfx::ARP::getHardwareType() const
{
    return (this->hw_type);
}

uint64_t        snfx::ARP::getProtocolType() const
{
    return (this->proto_type);
}

uint64_t        snfx::ARP::getHardwareLength() const
{
    return (this->hw_length);
}

uint64_t        snfx::ARP::getProtocolLength() const
{
    return (this->proto_length);
}

uint64_t        snfx::ARP::getARPcode() const
{
    return (this->opcode);
}