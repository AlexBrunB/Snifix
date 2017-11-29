#include    "UDP.hpp"

snfx::UDP::UDP(unsigned char *_data) : Packet(_data),
    udph((struct udphdr *)(_data + iphdrlen + sizeof(struct ethhdr))),
    protocol("UDP"),
    src_port(ntohs(udph->source)),
    dst_port(ntohs(udph->dest)),
    udp_length(ntohs(udph->len)),
    udp_checksum(ntohs(udph->check))
{
}

struct udphdr   *snfx::UDP::getUdph() const
{
    return (this->udph);
}

std::string     &snfx::UDP::getProtocol()
{
    return (this->protocol);
}

uint64_t        snfx::UDP::getSrcPort() const
{
    return (this->src_port);
}

uint64_t        snfx::UDP::getDstPort() const
{
    return (this->dst_port);
}

uint64_t        snfx::UDP::getUdpLength() const
{
    return (this->udp_length);
}

uint64_t        snfx::UDP::getUdpChecksum() const
{
    return (this->udp_checksum);
}
