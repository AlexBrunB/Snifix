# include "Record.hpp"

snfx::Record::Record(const std::string &_path) : 
	path(_path),
	data(""),
	stream_in(std::make_unique<std::ifstream>()),
	stream_out(std::make_unique<std::ofstream>()),
	packets(std::make_unique<std::vector<std::unique_ptr<Packet>>>()),
	packets_size(std::make_unique<std::vector<unsigned int>>()),
	epoch_ms_t(std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::system_clock::now().time_since_epoch())),
	epoch_s_t(std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()))
{
}

void	snfx::Record::writeGlobalHeader()
{
	pcaphdr.magic_number = 0xa1b2c3d4;
    pcaphdr.version_major = 2;
	pcaphdr.version_minor = 4;
	pcaphdr.thiszone = -3600;
	pcaphdr.sigfigs = 0;
	pcaphdr.snaplen = USHRT_MAX;
	pcaphdr.network = 1;
	stream_out.get()->open(path, std::ofstream::out | std::ofstream::binary);
	stream_out.get()->write((char*)&pcaphdr, sizeof(pcap_hdr_t));
	closeFile("out");

}
void	snfx::Record::writePacketHeader(const int size)
{
	pcaprechdr.ts_sec = 0;
	pcaprechdr.ts_usec = 0;
	pcaprechdr.incl_len = size;
	pcaprechdr.orig_len = pcaprechdr.incl_len;
	stream_out.get()->write((char*)&pcaprechdr, sizeof(pcaprec_hdr_t));
}

void	snfx::Record::writePacketData(Packet *packet, const int size)
{
	openFile("out");
	writePacketHeader(size);
	stream_out.get()->write((char*)packet->getData(), size);
	closeFile("out");
}

void	snfx::Record::readPcapFile()
{
	std::string	stream;
	openFile("in");
	data.clear();
	while (std::getline(*stream_in.get(), stream))
		data +=stream;
	closeFile("in");
}

void snfx::Record::openFile(const std::string &stream)
{
	if (stream.compare("in") == 0)
		stream_in.get()->open(path, std::ifstream::in | std::ifstream::binary);
	if (stream.compare("out") == 0)
		stream_out.get()->open(path, std::ofstream::out | std::ofstream::binary | std::ofstream::app);
}

void snfx::Record::closeFile(const std::string &stream)
{
	if (stream.compare("in") == 0)
		stream_in.get()->close();
	if (stream.compare("out") == 0)
		stream_out.get()->close();
}

std::string	&snfx::Record::getData()
{
	return (this->data);
}

void				snfx::Record::analysePcap(struct iphdr *iph)
{
	pcaprec_hdr_t	*pcaprec;
	uint32_t		offset;
	int				size_data;
	unsigned char	*buff;
	std::string		sub;
	std::string		sub2;
	std::unique_ptr<Packet>	packet;
	Visualize 		visual;

	readPcapFile();
	size_data = data.size();
	std::cout << "size_data : " << size_data << std::endl;
	offset = sizeof(pcap_hdr_t);
	size_data -= offset;
	std::cout << "size_data : " << size_data << std::endl;
	sub = data.substr(offset);
	while (size_data > 0)
	{
		std::cout << "size_data : " << size_data << std::endl;
		offset = 0;
		std::cout << "size sub : " << sub.size() << std::endl;

		pcaprec = (pcaprec_hdr_t *)(sub.c_str() + offset);
		printf("[9]%x ; [10]%x\n", (char)sub[9], (char)sub[10]);
		std::cout << "STRUCT PCAPREC : " << std::endl;
		std::cout << "pcaprec (incl_len) : " << pcaprec->incl_len << std::endl;
		offset = sizeof(pcaprec_hdr_t);
		std::cout << "SIZEOF PCAPREC : " << sizeof(pcaprec_hdr_t) << std::endl;
		std::cout << "INCL_LEN : " << pcaprec->incl_len << std::endl;
		sub2 = sub.substr(offset, pcaprec->incl_len);
		buff = (unsigned char *)sub2.c_str();
		iph = (struct iphdr *)(buff + sizeof(struct ethhdr));
		packet = snfx::PacketFactory::makePacket((uint64_t)iph->protocol, buff);
		if (packet != nullptr)
		{
    		packets.get()->push_back(std::move(packet));
			visual.showOnePacket(packets.get()->front().get(), sub2.size());
			packets_size.get()->push_back(static_cast<unsigned int>(sub2.size()));
		}
		else
			std::cerr << "packet null" << std::endl;
		offset += pcaprec->incl_len;
		sub = data.substr(offset + sizeof(pcap_hdr_t));
		size_data -= offset;
	}
}

std::vector<std::unique_ptr<snfx::Packet>> *snfx::Record::getPackets()
{
	return (this->packets.get());
}

std::vector<unsigned int>	*snfx::Record::getPacketsSize()
{
	return (this->packets_size.get());
}