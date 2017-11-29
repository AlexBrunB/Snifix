#ifndef __HTTP_HPP__
# define __HTTP_HPP__

# include "TCP.hpp"
# include <map>
# include <sstream>

namespace	snfx
{
  class		HTTP : public TCP
  {
  public:
    HTTP();
    HTTP(unsigned char *_data);
    virtual ~HTTP() {}
    size_t	getHttpHeaderLength();
    std::string &getFirstLine();
    std::string	&getInfo();
    std::string &getVersion();
    std::string &getConnection();
    std::string &getStatus();
    std::string &getResponsePhrase();
    std::string &getContent();
    std::string &getHost();
    std::string	&getUserAgent();
    std::string &getMethod();
    std::string &getUri();

  private:
    bool	isRequest();
    void	parseForRequest();
    void	parseForResponse();
    std::map<std::string, std::string>	*getMap();

  private:
    std::string	dataTmp;
    size_t	httpHeaderLength;
    std::string firstLine;
    std::string	info;
    std::string	version;
    std::string	connection;
    /**	Response attributes **/
    std::string	status;
    std::string	responsePhrase;
    std::string	content;
    /** Request attributes **/
    std::string	host;
    std::string userAgent;
    std::string method;
    std::string	uri;
  };
};

#endif	//__HTTP_HPP__
