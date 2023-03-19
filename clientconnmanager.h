#ifndef CLIENTCONNMANAGER_H
#define CLIENTCONNMANAGER_H

#include <mutex>
#include <map>
#include <stdint.h>
#include <memory>

class ClientConnection;
class ClientConnManager
{
public:
    ClientConnManager();
    std::shared_ptr<ClientConnection> createConnection(int fd);
    void releaseConnection(uint32_t connId);
private:
    uint32_t m_nextConnId;
    std::mutex m_mutex;
    std::map<uint32_t, std::shared_ptr<ClientConnection>> m_mapConnection;
};

#endif // CLIENTCONNMANAGER_H
