#include "clientconnection.h"

ClientConnection::ClientConnection(uint32_t connId, int sockfd) :  m_connID{connId}, m_nextStreamId{1}, m_rtmp{NULL}, m_streamType{Unkown}, m_unPublishFlag{false}
{
    m_rtmp = RTMP_Alloc();  // 分配RTMP上下文
    RTMP_Init(m_rtmp); //初始化RTMP上下文，设默认值
    m_rtmp->m_sb.sb_socket = sockfd;
    sem_init(&m_sem, 0, 0);
}

ClientConnection::~ClientConnection()
{
    RTMP_Close(m_rtmp);  //关闭RTMP连接
    RTMP_Free(m_rtmp);  //释放结构体"RTMP"
    sem_destroy(&m_sem);
}

uint32_t ClientConnection::genStreamId()
{
    uint32_t streamId = m_nextStreamId++;
    m_setUsingStreamId.insert(streamId);
    return streamId;
}

bool ClientConnection::isValidStreamId(uint32_t streamId)
{
    return m_setUsingStreamId.find(streamId) != m_setUsingStreamId.end();
}


