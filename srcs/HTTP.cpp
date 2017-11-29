#include "HTTP.hpp"

snfx::HTTP::HTTP(unsigned char *_data) : TCP(_data),
					 dataTmp(reinterpret_cast<char const*>(_data +
									       sizeof(struct ethhdr) +
									       getIphdrlen() +
									       getTcph()->doff * 4))
{
  size_t	tmp;

  protocol = "HTTP";
  tmp = dataTmp.find("Cache-Control: ");
  httpHeaderLength = dataTmp.find("\r\n\r\n", tmp) + 4;
  content = dataTmp.substr(httpHeaderLength);
  firstLine = dataTmp.substr(0, dataTmp.find("\r\n"));
  if (isRequest())
    parseForRequest();
  else
    parseForResponse();
}

size_t	snfx::HTTP::getHttpHeaderLength()
{
  return httpHeaderLength;
}

std::string	&snfx::HTTP::getFirstLine()
{
  return firstLine;
}

std::string	&snfx::HTTP::getInfo()
{
  return info;
}

std::string	&snfx::HTTP::getVersion()
{
  return version;
}

std::string	&snfx::HTTP::getConnection()
{
  return connection;
}

std::string	&snfx::HTTP::getStatus()
{
  return status;
}

std::string	&snfx::HTTP::getResponsePhrase()
{
  return responsePhrase;
}

std::string	&snfx::HTTP::getContent()
{
  return content;
}

std::string	&snfx::HTTP::getHost()
{
  return host;
}

std::string	&snfx::HTTP::getUserAgent()
{
  return userAgent;
}

std::string	&snfx::HTTP::getMethod()
{
  return method;
}

std::string	&snfx::HTTP::getUri()
{
  return uri;
}

std::map<std::string, std::string>	*snfx::HTTP::getMap()
{
  std::string		currline;
  std::istringstream	iss(dataTmp);
  size_t		delim;
  std::map<std::string, std::string>	*map = new std::map<std::string, std::string>();

  while (std::getline(iss, currline))
    {
      if ((delim = currline.find(": ")) != std::string::npos && currline.back() == '\r')
	{
	  currline.pop_back();
	  map->insert(std::make_pair<std::string, std::string>(currline.substr(0, delim),
							       currline.substr(delim + 2)));
	}
    }
  return map;
}

bool	snfx::HTTP::isRequest()
{
  if (firstLine.find("GET") != std::string::npos ||
      firstLine.find("HEAD") != std::string::npos ||
      firstLine.find("POST") != std::string::npos ||
      firstLine.find("OPTIONS") != std::string::npos ||
      firstLine.find("CONNECT") != std::string::npos ||
      firstLine.find("TRACE") != std::string::npos ||
      firstLine.find("PUT") != std::string::npos ||
      firstLine.find("PATCH") != std::string::npos ||
      firstLine.find("DELETE") != std::string::npos)
    {
      info += "Request";
      return true;
    }
  info += "Response";
  return false;
}

void	snfx::HTTP::parseForRequest()
{
  size_t	nextSpace = firstLine.find(" ");
  size_t	index = nextSpace + 1;
  std::map<std::string, std::string>	*map;

  method = firstLine.substr(0, nextSpace);
  nextSpace = firstLine.find(" ", index);
  uri = firstLine.substr(index, nextSpace - index);
  index = nextSpace + 1;
  version = firstLine.substr(index);
  map = getMap();
  connection = (*map)["Connection"];
  host = (*map)["Host"];
  userAgent = (*map)["User-Agent"];
  delete map;
}

void	snfx::HTTP::parseForResponse()
{
  size_t	nextSpace = firstLine.find(" ");
  size_t	index = nextSpace + 1;
  std::map<std::string, std::string>	*map;

  version = firstLine.substr(0, nextSpace);
  nextSpace = firstLine.find(" ", index);
  status = firstLine.substr(index, nextSpace - index);
  index = nextSpace + 1;
  responsePhrase = firstLine.substr(index);
  map = getMap();
  connection = (*map)["Connection"];
  delete map;
}
