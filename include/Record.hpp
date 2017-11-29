#ifndef		__RECORD_HPP__
# define	__RECORD_HPP__

# include <cstdint>
# include <pcap.h>
# include <fstream>
# include <memory>
# include <vector>
# include <ctime>
# include <climits>
# include <chrono>
# include <iomanip>
# include "Packet.hpp"
# include "ICMP.hpp"
# include "Visualize.hpp"
# include "PacketFactory.hpp"

typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

namespace	snfx
{

	class	Record
	{
	public:
	    Record();
	    explicit Record(const std::string &_path);
	    virtual ~Record() {};
	    void writeGlobalHeader();
	    void writePacketHeader(const int size);
	    void writePacketData(Packet *packet, const int size);
		void readPcapFile();
		void openFile(const std::string &stream);
	    void closeFile(const std::string &stream);
		void analysePcap(struct iphdr *iph);
		std::vector<std::unique_ptr<Packet>> *getPackets();
		std::vector<unsigned int>	*getPacketsSize();
		std::string	&getData();
	private:
		std::string	path;
		std::string	data;
	    std::unique_ptr<std::ifstream> stream_in;
		std::unique_ptr<std::ofstream> stream_out;
		std::unique_ptr<std::vector<std::unique_ptr<Packet>>> packets;
		std::unique_ptr<std::vector<unsigned int>>	packets_size;
	    std::chrono::microseconds epoch_ms_t;
	    std::chrono::seconds epoch_s_t;
	    pcap_hdr_t 	pcaphdr;
	    pcaprec_hdr_t pcaprechdr;
	};
};

#endif		//__RECORD_HPP__
