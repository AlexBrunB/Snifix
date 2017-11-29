#ifndef     __TCP_HPP__
# define    __TCP_HPP__

# include   <string>
# include   <netinet/tcp.h>
# include   "Packet.hpp"

namespace   snfx
{
    class   TCP : public Packet
    {
        public:
                    TCP();
                    TCP(unsigned char *_data);
            virtual ~TCP() {};
            std::string &getProtocol();
            uint64_t    getSrcPort() const;
            uint64_t    getDstPort() const;
            uint64_t    getSeqNumber() const;
            uint64_t    getAckNumber() const;
            uint64_t    getLenTCPHeader(const std::string &type) const;
            uint64_t    getUrgentFlag() const;
            uint64_t    getAckFlag() const;
            uint64_t    getPshFlag() const;
            uint64_t    getRstFlag() const;
            uint64_t    getSynFlag() const;
            uint64_t    getFinFlag() const;
            uint64_t    getWindow() const;
            uint64_t    getTCPChecksum() const;
            uint64_t    getUrgentPointer() const;
            struct tcphdr *getTcph() const;
	private:
            struct tcphdr *tcph;
	protected:
	   std::string protocol;
            uint64_t    src_port;
            uint64_t    dst_port;
            uint64_t    seq_num;
            uint64_t    ack_num;
            uint64_t    len_tcp_head_dwords;
            uint64_t    len_tcp_head_bytes;
            uint64_t    urgent_flag;
            uint64_t    ack_flag;
            uint64_t    psh_flag;
            uint64_t    rst_flag;
            uint64_t    syn_flag;
            uint64_t    fin_flag;
            uint64_t    window;
            uint64_t    tcp_checksum;
            uint64_t    urg_ptr;
    };
};

#endif      //__TCP_HPP_
