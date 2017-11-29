#include    "ICMP.hpp"

snfx::ICMP::ICMP(unsigned char *_data) : Packet(_data),
    icmph((struct icmphdr *)(data + iphdrlen + sizeof(struct ethhdr))),
    protocol("ICMP"),
    response(""),
    type(icmph->type),
    code(icmph->code),
    icmp_checksum(ntohs(icmph->checksum))
{
}

struct icmphdr  *snfx::ICMP::getIcmph() const
{
    return (this->icmph);
}

std::string     &snfx::ICMP::getProtocol()
{
    return (this->protocol);
}

std::string     &snfx::ICMP::getResponse()
{
    if(icmph->type == 11)
        response.assign("(TTL Expired)");
    else if(icmph->type == ICMP_ECHOREPLY)
        response.assign("(ICMP Echo Reply)");
    return (this->response);
}

uint64_t        snfx::ICMP::getType() const
{
    return (this->type);
}

uint64_t        snfx::ICMP::getCode() const
{
    return (this->code);
}

uint64_t        snfx::ICMP::getICMPChecksum() const
{
    return (this->icmp_checksum);
}