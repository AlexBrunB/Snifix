#include "ForgingTCP.hpp"

snfx::ForgingTCP::ForgingTCP() :
    content(""),
    src_addr(""),
    dst_addr(""),
    src_port(0),
    dst_port(0),
    id_packet(0),
    raw_sock(0),
    datagram(std::make_unique<char[]>(4096)),
    src_ip(std::make_unique<char[]>(32)),
    pseudogram(nullptr),
    data(nullptr),
    iph(nullptr),
    tcph(nullptr),
    psize(0),
    one(1),
    val(&one)
{
}

unsigned short      snfx::ForgingTCP::calcChecksum(unsigned short *data, int size)
{
    long            sum;
    unsigned short  oddbyte;
    short           answer;

    sum = 0;
    oddbyte = 0;
    answer = 0;
    while (size > 1)
    {
        sum += *data++;
        size -= 2;
    }
    if (size == 1)
    {
        *((u_char*)&oddbyte) = *(u_char*)data;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (answer);
}

bool    snfx::ForgingTCP::initPacket()
{
    if ((raw_sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        std::cerr << "Failed to create socket" << std::endl;
        return (false);
    }
    iph = (struct iphdr *)(datagram.get());
    tcph = (struct tcphdr *)(datagram.get() + sizeof(struct ip));
    data = datagram.get() + sizeof(struct iphdr) + sizeof(struct tcphdr);
    std::strcpy(data, content.c_str());
    std::strcpy(src_ip.get(), src_addr.c_str());
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = inet_addr(dst_addr.c_str());
    fillIph();
    fillPsh();
    fillTcph();
    return (true);
}

void    snfx::ForgingTCP::fillIph()
{
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + std::strlen(data);
    iph->id = htonl(id_packet);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(src_ip.get());
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = calcChecksum((unsigned short *)datagram.get(), iph->tot_len);
}

void    snfx::ForgingTCP::fillTcph()
{
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

void    snfx::ForgingTCP::fillPsh()
{
    psh.src_addr = inet_addr(src_ip.get());
    psh.dst_addr = sin.sin_addr.s_addr;
    psh.placeholder = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + std::strlen(data));
    psize = sizeof(fHeaderTCP_t) + sizeof(struct tcphdr) + std::strlen(data);
    pseudogram = std::make_unique<char[]>(psize);
    std::memcpy(pseudogram.get(), (char *)&psh, sizeof(fHeaderTCP_t));
    std::memcpy(pseudogram.get() + sizeof(fHeaderTCP_t), tcph, sizeof(struct tcphdr) + std::strlen(data));
    tcph->check = calcChecksum((unsigned short *)(pseudogram.get()), psize);
}

bool    snfx::ForgingTCP::sendPacket()
{
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        std::cerr << "Error setting IP_HDRINCL" << std::endl;
        return (false);
    }
    if (sendto(raw_sock, datagram.get(), iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        std::cerr << "Sendto failed" << std::endl;
        return (false);
    }
    close(raw_sock);
    return (true);
}

bool    snfx::ForgingTCP::makePacket(contentPacket_t    &contentPacket)
{
    content = contentPacket.content;
    src_addr = contentPacket.src_addr;
    dst_addr = contentPacket.dst_addr;
    src_port = contentPacket.src_port;
    dst_port = contentPacket.dst_port;
    id_packet = contentPacket.id_packet;
    if (!initPacket())
        return (false);
    return (true);
}