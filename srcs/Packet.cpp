#include "Packet.hpp"

snfx::Packet::Packet(unsigned char *_data) :
    src_mac(),
    dst_mac(),
    src_ip(),
    dst_ip(),
    ip_version(0),
    len_head_dwords(0),
    len_head_bytes(0),
    ttl(0),
    len_packet(0),
    checksum(0),
    id_packet(0),
    data(_data),
    eth((struct ethhdr *)(this->data)),
    iph((struct iphdr *)(this->data + sizeof(struct ethhdr))),
    iphdrlen(this->iph->ihl * 4)
{
    std::stringstream   stream;

    stream  << std::hex << (uint64_t)eth->h_source[0] << "-"
            << std::hex << (uint64_t)eth->h_source[1] << "-"
            << std::hex << (uint64_t)eth->h_source[2] << "-"
            << std::hex << (uint64_t)eth->h_source[3] << "-"
            << std::hex << (uint64_t)eth->h_source[4] << "-"
            << std::hex << (uint64_t)eth->h_source[5];
    this->src_mac = stream.str();
    stream.str("");
    stream  << std::hex << (uint64_t)eth->h_dest[0] << "-"
            << std::hex << (uint64_t)eth->h_dest[1] << "-"
            << std::hex << (uint64_t)eth->h_dest[2] << "-"
            << std::hex << (uint64_t)eth->h_dest[3] << "-"
            << std::hex << (uint64_t)eth->h_dest[4] << "-"
            << std::hex << (uint64_t)eth->h_dest[5];
    this->dst_mac = stream.str();
    std::memset(&s_src, 0, sizeof(s_src));
    std::memset(&s_dst, 0, sizeof(s_dst));
    s_src.sin_addr.s_addr = iph->saddr;
    src_ip = std::string(inet_ntoa(s_src.sin_addr));
    s_dst.sin_addr.s_addr = iph->daddr;
    dst_ip = std::string(inet_ntoa(s_dst.sin_addr));
    ip_version = (uint64_t)iph->version;
    len_head_dwords = (uint64_t)iph->ihl;
    len_head_bytes = (uint64_t)(iph->ihl * 4);
    ttl = (uint64_t)(iph->ttl);
    len_packet = ntohs(iph->tot_len);
    checksum = ntohs(iph->check);
    id_packet = ntohs(iph->id);
}

std::string     &snfx::Packet::getSrcMAC()
{
    return (this->src_mac);
}

std::string     &snfx::Packet::getDstMAC()
{
    return (this->dst_mac);
}

std::string     &snfx::Packet::getSrcIP()
{
    return (this->src_ip);
}

std::string     &snfx::Packet::getDstIP()
{
    return (this->dst_ip);
}

uint64_t        snfx::Packet::getIpVersion() const
{
    return (this->ip_version);
}

uint64_t        snfx::Packet::getLenHeader(const std::string &type) const
{
    if (type.compare("dwords") == 0)
    {
        return (this->len_head_dwords);
    }
    else if (type.compare("bytes") == 0)
    {
        return (this->len_head_bytes);
    }
    else
    {
        return (EXIT_FAILURE);
    }
}

uint64_t        snfx::Packet::getTTL() const
{
    return (this->ttl);
}

uint64_t        snfx::Packet::getLenPacket() const
{
    return (this->len_packet);
}

uint64_t        snfx::Packet::getChecksum() const
{
    return (this->checksum);
}

uint64_t        snfx::Packet::getIdPacket() const
{
    return (this->id_packet);
}

unsigned char *snfx::Packet::getData()
{
    return (this->data);
}

unsigned short  snfx::Packet::getIphdrlen() const
{
    return (this->iphdrlen);
}

struct ethhdr   *snfx::Packet::getEthhdr() const
{
    return (this->eth);
}

struct iphdr    *snfx::Packet::getIphdr() const
{
    return (this->iph);
}