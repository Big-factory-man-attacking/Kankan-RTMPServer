#ifndef CLIENTCONNECTION_H
#define CLIENTCONNECTION_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <set>
#include <map>
#include <mutex>
#include <semaphore.h>


class ClientConnection
{
public:
    // 流类型
    enum EStreamType
    {
        Unkown = 0,
        Publish,
        Play
    };
    ClientConnection(uint32_t connId, int sockfd);
    ~ClientConnection();
    uint32_t connId() {return m_connID;}
    RTMP* rtmp() {return m_rtmp;}
    int socket() {return m_rtmp->m_sb.sb_socket;}
    EStreamType streamType() {return (EStreamType)m_streamType;}
    void setStreamType(EStreamType type) {m_streamType = type;}

    uint32_t genStreamId();
    bool isValidStreamId(uint32_t streamId);
    void setUnPublishFlag(bool flag) {m_unPublishFlag = flag;}
    bool unPublishFlag() {return m_unPublishFlag;}
    std::string videoPath() {return m_videoPath;}
    void setVideoPath(std::string videoPath) {m_videoPath = videoPath;}
private:
    uint32_t m_connID;
    uint32_t m_nextStreamId;
    RTMP* m_rtmp;
    int m_streamType;
    std::mutex m_mutex;
    sem_t m_sem;
    std::set<uint32_t> m_setUsingStreamId;
    bool m_unPublishFlag;
    std::string m_videoPath;
};


#endif // CLIENTCONNECTION_H
