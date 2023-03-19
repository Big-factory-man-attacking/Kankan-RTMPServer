#include "clientconnmanager.h"
#include "clientconnection.h"
ClientConnManager::ClientConnManager():m_nextConnId{1}
{

}

std::shared_ptr<ClientConnection> ClientConnManager::createConnection(int fd)
{
    std::lock_guard<std::mutex> lock(m_mutex);
   // ClientConnection* conn = new ClientConnection(m_nextConnId, fd);
    auto conn = std::make_shared<ClientConnection>(m_nextConnId, fd);
    m_mapConnection[conn->connId()] = conn;
    return conn;
}

void ClientConnManager::releaseConnection(uint32_t connId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_mapConnection.erase(connId);
}

