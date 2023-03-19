#ifndef RTMPSERVER_H
#define RTMPSERVER_H

#include <memory>
#include "clientconnmanager.h"
#include "clientconnection.h"
#include "threadpool.h"

class RtmpServer
{
public:
    RtmpServer(int threadNum);
    void initSocket();
    void start();
    //推流
    void analysePacket(std::shared_ptr<ClientConnection> conn);
    //拉流
    void play(std::shared_ptr<ClientConnection> conn);
private:
    int m_listenfd;
    std::unique_ptr<ClientConnManager> m_manager;
    std::unique_ptr<ThreadPool> m_threadPool;

    void writeFlvTag(uint8_t tagType, uint32_t tagSize, uint32_t bodySize, uint32_t timestamp, char *body, FILE* flvFile);
    //报文分派交互处理
    bool dispatch(std::shared_ptr<ClientConnection> conn, RTMPPacket* pPacket, FILE* pFile = nullptr);
    //握手
    bool myHandShake(int sockfd);
    //处理远程调用
    int HandleInvoke(std::shared_ptr<ClientConnection> conn, RTMPPacket* pPacket);

    bool sendWindowAckSize(std::shared_ptr<ClientConnection> pConn);
    bool sendPeerOutputBandWide(std::shared_ptr<ClientConnection> pConn);
    bool sendOutputChunkSize(std::shared_ptr<ClientConnection> pConn);
    bool sendConnectResult(std::shared_ptr<ClientConnection> pConn, int nOperateID);
    bool sendCreateStreamResult(std::shared_ptr<ClientConnection> pConn, int nOperateID, uint32_t nStreamID);
    bool sendPublishStatus(std::shared_ptr<ClientConnection> pConn, int nInputStreamID);
    bool sendPublishError(std::shared_ptr<ClientConnection> pConn, int nInputStreamID);
    // 发送拉流事件报文
    bool sendPlayStreamBegin(std::shared_ptr<ClientConnection> pConn, int nInputStreamID);
    // 发送拉流状态响应报文
    bool sendPlayStatus(std::shared_ptr<ClientConnection> pConn, int nInputStreamID);
};

#endif // RTMPSERVER_H
