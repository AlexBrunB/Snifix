#include "TCP.hpp"

snfx::Packet::~Packet()
{
    
}

snfx::TCP::TCP(unsigned char *_data) : Packet(_data),
    tcph((struct tcphdr *)(_data + iphdrlen + sizeof(struct ethhdr))),
    protocol("TCP"),
    src_port(ntohs(tcph->source)),
    dst_port(ntohs(tcph->dest)),
    seq_num(ntohl(tcph->seq)),
    ack_num(ntohl(tcph->ack_seq)),
    len_tcp_head_dwords(tcph->doff),
    len_tcp_head_bytes(tcph->doff * 4),
    urgent_flag(tcph->urg),
    ack_flag(tcph->ack),
    psh_flag(tcph->psh),
    rst_flag(tcph->rst),
    syn_flag(tcph->syn),
    fin_flag(tcph->fin),
    window(ntohs(tcph->window)),
    tcp_checksum(ntohs(tcph->check)),
    urg_ptr(tcph->urg_ptr)
{   
}

std::string     &snfx::TCP::getProtocol()
{
    return (this->protocol);
}

uint64_t        snfx::TCP::getSrcPort() const
{
    return (this->src_port);
}

uint64_t        snfx::TCP::getDstPort() const
{
    return (this->dst_port);
}

uint64_t        snfx::TCP::getSeqNumber() const
{
    return (this->seq_num);
}

uint64_t        snfx::TCP::getAckNumber() const
{
    return (this->ack_num);
}

uint64_t        snfx::TCP::getLenTCPHeader(const std::string &type) const
{
    if (type.compare("dwords") == 0)
    {
        return (this->len_tcp_head_dwords);
    }
    else if (type.compare("bytes") == 0)
    {
        return (this->len_tcp_head_bytes);
    }
    else
    {
        return (EXIT_FAILURE);
    }
}

uint64_t        snfx::TCP::getUrgentFlag() const
{
    return (this->urgent_flag);
}

uint64_t        snfx::TCP::getAckFlag() const
{
    return (this->ack_flag);
}

uint64_t        snfx::TCP::getPshFlag() const
{
    return (this->psh_flag);
}

uint64_t        snfx::TCP::getRstFlag() const
{
    return (this->rst_flag);
}

uint64_t        snfx::TCP::getSynFlag() const
{
    return (this->syn_flag);
}

uint64_t        snfx::TCP::getFinFlag() const
{
    return (this->fin_flag);
}

uint64_t        snfx::TCP::getWindow() const
{
    return (this->window);
}

uint64_t        snfx::TCP::getTCPChecksum() const
{
    return (this->tcp_checksum);
}

uint64_t        snfx::TCP::getUrgentPointer() const
{
    return (this->urg_ptr);
}

struct tcphdr   *snfx::TCP::getTcph() const
{
    return (this->tcph);
}