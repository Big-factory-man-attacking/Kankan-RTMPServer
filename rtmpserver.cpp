#include "rtmpserver.h"
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <thread>

#include <librtmp/rtmp.h>
#include <librtmp/log.h>

#define SAVC(x) static const AVal av_##x = AVC(#x)
SAVC(connect);
SAVC(_result);
SAVC(releaseStream);
SAVC(FCPublish);
SAVC(createStream);
SAVC(publish);
SAVC(onStatus);
SAVC(FCUnpublish);
SAVC(deleteStream);
SAVC(play);

// 大小端字节序转换
#define HTON16(x) ( (x >> 8 & 0x00FF) | (x << 8 & 0xFF00) )
#define HTON24(x) ( (x >> 16 & 0x0000FF) | (x & 0x00FF00) | (x << 16 & 0xFF0000) )
#define HTON32(x) ( (x >> 24 & 0x000000FF) | (x >> 8 & 0x0000FF00) | (x << 8 & 0x00FF0000) | (x << 24 & 0xFF000000) )
#define HTONTIME(x) ( (x >> 16 & 0x000000FF) | (x & 0x0000FF00) | (x << 16 & 0x00FF0000) | (x & 0xFF000000) )

// 从文件读取指定字节
bool ReadFP(char* pBuf, int nSize, FILE* pFile)
{
    return (fread(pBuf, 1, nSize, pFile) == nSize);
}

// 从文件读取1个字节整数
bool ReadU8(uint8_t* u8, FILE* fp)
{
    return ReadFP((char*)u8, 1, fp);
}

// 从文件读取2个字节整数
bool ReadU16(uint16_t* u16, FILE* fp)
{
    if (!ReadFP((char*)u16, 2, fp))
        return false;

    *u16 = HTON16(*u16);
    return true;
}

// 从文件读取3个字节整数
bool ReadU24(uint32_t* u24, FILE* fp)
{
    if (!ReadFP((char*)u24, 3, fp))
        return false;

    *u24 = HTON24(*u24);
    return true;
}

// 从文件读取4个字节整数
bool ReadU32(uint32_t* u32, FILE* fp)
{
    if (!ReadFP((char*)u32, 4, fp))
        return false;

    *u32 = HTON32(*u32);
    return true;
}

// 从文件读取4个字节时间戳
bool ReadTime(uint32_t* utime, FILE* fp)
{
    if (!ReadFP((char*)utime, 4, fp))
        return false;

    *utime = HTONTIME(*utime);
    return true;
}

// 从文件预读1个字节整数
bool PeekU8(uint8_t* u8, FILE* fp)
{
    if (!ReadFP((char*)u8, 1, fp))
        return false;

    fseek(fp, -1, SEEK_CUR);
    return true;
}


AVal makeAVal(const char* pStr)
{
    return {(char*)pStr, (int)strlen(pStr)};
}




RtmpServer::RtmpServer(int threadNum) : m_manager{new ClientConnManager}, m_threadPool{new ThreadPool(threadNum)}
{
    initSocket();
}

void RtmpServer::initSocket()
{
    RTMP_LogSetLevel(RTMP_LOGDEBUG);
   m_listenfd = socket(AF_INET, SOCK_STREAM, 0);
   int nFlag = 1;
   setsockopt(m_listenfd, SOL_SOCKET, SO_REUSEADDR, (char*)&nFlag, sizeof(nFlag));
   struct sockaddr_in addr;
   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr = INADDR_ANY;
   addr.sin_port = htons(1936);

   int ret = bind(m_listenfd, (struct sockaddr*)&addr, sizeof(addr));
   if (ret < 0) {
       std::cerr << "绑定失败" << std::endl;
       return;
   }

   listen(m_listenfd, 20);
}

void RtmpServer::start()
{
    while (true) {
        int fd = accept(m_listenfd, NULL, NULL);
        if (fd < 0) {
            std::cerr << "accept() failed! \n";
            return;
        }
        int nFlag = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&nFlag, sizeof(nFlag));  //关闭Nagle算法
        auto conn = m_manager->createConnection(fd);
        m_threadPool->AddTask(std::bind(&RtmpServer::analysePacket, this, conn));
    }
}
void RtmpServer::play(std::shared_ptr<ClientConnection> conn)
{
    std::string videoName = conn->videoPath();
    std::string fileDir = __FILE__;
    int n = fileDir.size() - 1;
    for (; n > 0; --n) {
        if (fileDir[n] == '/') break;
    }
    std::string filePath = fileDir.substr(0, n + 1) + "/media/" + conn->videoPath() + ".flv";
    FILE* pFile = fopen(filePath.c_str(), "rb");
    if (!pFile) {
        printf("open file failed!");
    }

    // 跳过FLV文件头的13个字节
    fseek(pFile, 9, SEEK_SET);
    fseek(pFile, 4, SEEK_CUR);

    // 初使化RTMP报文
    RTMPPacket packet;
    RTMPPacket_Reset(&packet);
    packet.m_body = NULL;
    packet.m_chunk = NULL;
    packet.m_nInfoField2 = conn->rtmp()->m_stream_id;


//    struct timeval tv;
//    gettimeofday(&tv, NULL);
//    double lastReadTime = tv.tv_sec + tv.tv_usec / (double)1000000;

    uint32_t starttime = RTMP_GetTime();

    while (true) {
        //读取TAG头
        uint8_t type = 0;
        if (!ReadU8(&type, pFile)) break;

        uint32_t dataLen = 0;
        if (!ReadU24(&dataLen, pFile)) break;

        uint32_t timeStamp = 0;
        if (!ReadTime(&timeStamp, pFile)) break;

        uint32_t streamId = 0;
        if (!ReadU24(&streamId, pFile)) break;

        RTMPPacket_Alloc(&packet, dataLen);

        if (fread(packet.m_body, 1, dataLen, pFile) != dataLen) break;

        //组织包发送
        packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
        packet.m_packetType = type;
        packet.m_hasAbsTimestamp = 0;
        packet.m_nChannel = 6;  //块流id
        packet.m_nTimeStamp = timeStamp;
        packet.m_nBodySize = dataLen;

        if (!RTMP_SendPacket(conn->rtmp(), &packet, 0)) {
            printf("Send Error! \n");
            break;
        }

        printf("send type:[%d] timestamp:[%d] datasize:[%d] \n", type, timeStamp, dataLen);

        //跳过PreTag
        uint32_t preTagSize = 0;
        if (!ReadU32(&preTagSize, pFile)) break;

        //延时，避免发送
        uint32_t timeAgo = (RTMP_GetTime() - starttime);
        if (timeStamp > 1000 && timeAgo < timeStamp - 1000) {
            printf("sleep....\n");
            usleep(100000);
        }

        RTMPPacket_Free(&packet);
    }

    fclose(pFile);
}

void RtmpServer::analysePacket(std::shared_ptr<ClientConnection> conn)
{
    printf("connection:[%d] coming... \n", conn->connId());
    // 握手
    bool b = myHandShake(conn->socket());
    if (!b) {
        std::cout << "connection:[%d] handshake failed!" << conn->connId() << std::endl;
        m_manager->releaseConnection(conn->connId());
        return;
    }

    FILE* pFile;
   // std::thread::id this_id = std::this_thread::get_id();
    int id = syscall(SYS_gettid);  //获取当前线程id

    std::string path = "/tmp/" + std::to_string(id) + ".flv";   //将客户端推过来的数据写入临时文件
    if ((pFile =fopen(path.c_str(), "wb")) == NULL) {
        std::cerr << "cannot open the file\n";
        return;
    }
    //写FLV文件头
   const char flvHeader[] = {
       'F','L','V', //固定签名
        0x01, //FLV版本号
        0x05, //数据类型，0x01表示视频，0x04表示音频，0x05表示音视频都有
        0x00, 0x00, 0x00, 0x09, //FLV头长度
        0x00, 0x00, 0x00, 0x00  //首个TAG前的固定Size，永远为0
   };
   fwrite(flvHeader, 13, 1, pFile);
   fflush(pFile);


   while (true) {
       RTMPPacket packet;
       packet.m_body = nullptr;
       packet.m_chunk = nullptr;
       RTMPPacket_Reset(&packet);
       //读取报文
        if (!RTMP_ReadPacket(conn->rtmp(), &packet)) {
            std::cout << "connection:[" << conn->connId() << "] read error!" << std::endl;
            break;
        }

        if (!RTMPPacket_IsReady(&packet)) continue;

        printf("connection:[%d] read headerType:[%d] packetType:[%d] CSID:[%d] StreamID:[%d] hasAbsTimestamp:[%d] nTimeStamp:[%d] m_nBodySize:[%d] \n",
               conn->connId(), packet.m_headerType, packet.m_packetType, packet.m_nChannel, packet.m_nInfoField2, packet.m_hasAbsTimestamp, packet.m_nTimeStamp, packet.m_nBodySize);

        bool b = dispatch(conn, &packet, pFile);   //报文分派交互
        RTMPPacket_Free(&packet);

        if (!b) {
            std::cout << "connection:[%d] Dispatch failed! " << conn->connId() << std::endl;
            break;
        }
        if (conn->streamType() == ClientConnection::Play) {
            fclose(pFile);
            std::string cmdRm = "rm -f " + path;
            system(cmdRm.c_str());
            break;
        }
   }

   if (conn->streamType() == ClientConnection::Publish) {
        fclose(pFile);
        //获取当前文件所在目录
        std::string fileDir = __FILE__;
        int n = fileDir.size() - 1;
        for (; n > 0; --n) {
            if (fileDir[n] == '/') break;
        }
        std::string filePath = fileDir.substr(0, n) + "/media/" + conn->videoPath() + ".flv";
        std::string cmdMv = "mv " + path + " " + filePath;
        system(cmdMv.c_str());  //将临时文件移动到服务器目录下
        std::string cmdRm = "rm -f " + path;    //删除临时文件
        system(cmdRm.c_str());
   }

   //进入拉流状态
   if (conn->streamType() == ClientConnection::Play) {
        play(conn);
   }
   m_manager->releaseConnection(conn->connId());
}


//握手操作
#define RTMP_SIG_SIZE 1536
bool RtmpServer::myHandShake(int sockfd)
{

    char type = 0;
    if (recv(sockfd, (char*)&type, 1, 0) != 1) return false;
    if (type != 3) return false;

    char sClientSIG[RTMP_SIG_SIZE] = {0};
    if (recv(sockfd, sClientSIG, RTMP_SIG_SIZE, 0) != RTMP_SIG_SIZE) return false;

    if (send(sockfd, sClientSIG, RTMP_SIG_SIZE, 0) != RTMP_SIG_SIZE) return false;

    char sServerSIG[1+RTMP_SIG_SIZE] = {0};
    sServerSIG[0] = 3;

    if (send(sockfd, sServerSIG, 1 + RTMP_SIG_SIZE, 0) != 1 + RTMP_SIG_SIZE) return false;

    if (recv(sockfd, sServerSIG + 1, RTMP_SIG_SIZE, 0) != RTMP_SIG_SIZE) return false;

    return true;

}

int RtmpServer::HandleInvoke(std::shared_ptr<ClientConnection> conn, RTMPPacket *pPacket)
{
    if (pPacket->m_body[0] != 0x02)
    {
        printf("connection:[%d] invalid invoke! \n", conn->connId());
        return -1;
    }

    uint32_t nInputStreamID = pPacket->m_nInfoField2;

    AMFObject obj;
    int nSize = AMF_Decode(&obj, pPacket->m_body, pPacket->m_nBodySize, FALSE);
    if (nSize < 0)
    {
        printf("connection:[%d] invalid packet! \n", conn->connId());
        return -1;
    }

    AVal method;
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &method);
    int nOperateID = (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 1));
    printf("connection:[%d] server invoking <%s> %d \n", conn->connId(), method.av_val, nOperateID);

    if (AVMATCH(&method, &av_connect)) {
//        AMFObject obj1;
//        AMFProp_GetObject(AMF_GetProp(&obj, NULL, 2), &obj1);

//        AVal appName = makeAVal("app");
//        AVal app;
//        AMFProp_GetString(AMF_GetProp(&obj1, &appName, -1), &app);

//        std::string strApp(app.av_val, app.av_len);
        printf("connection:[%d] connect \n", conn->connId());

     //   pConn->setAppName(strApp);

        if (!sendWindowAckSize(conn))
            return -1;

        if (!sendPeerOutputBandWide(conn))
            return -1;

        if (!sendOutputChunkSize(conn))
            return -1;

        if (!sendConnectResult(conn, nOperateID))
            return -1;
    } else if (AVMATCH(&method, &av_releaseStream)) {
        AVal playpath;
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &playpath);

        std::string strPlayPath(playpath.av_val, playpath.av_len);
        printf("connection:[%d] releaseStream, playpath:[%s] \n", conn->connId(), strPlayPath.c_str());

        // 检查该节目是否推流结束
    //    CPlayPath* pPlayPath = g_Apps.getApp(pConn->getAppName())->getPlayPath(strPlayPath, true);
//        if (!pPlayPath->isEOF())
//        {
        if (conn->unPublishFlag()) {
            if (!sendPublishError(conn, nInputStreamID)) return -1;
            return 0;
        }
     //   }

        // 重置节目
    //    pPlayPath->reset(false);
    } else if (AVMATCH(&method, &av_FCPublish)) {
        AVal playpath;
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &playpath);

        std::string strPlayPath(playpath.av_val, playpath.av_len);
        printf("connection:[%d] FCPublish, playpath:[%s] \n", conn->connId(), strPlayPath.c_str());

        // 安全起见，初使化节目
     //   g_Apps.getApp(pConn->getAppName())->getPlayPath(strPlayPath, true);
    } else if (AVMATCH(&method, &av_createStream)) {
        // 生成流ID
        uint32_t uStreamID = conn->genStreamId();

        printf("connection:[%d] createStream, streamID:[%d] \n", conn->connId(), uStreamID);

        if (!sendCreateStreamResult(conn, nOperateID, uStreamID))
            return -1;
    } else if (AVMATCH(&method, &av_publish)) {
        AVal playpath;
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &playpath);

        std::string strPlayPath(playpath.av_val, playpath.av_len);
        //设置要上传视频的名字
        conn->setVideoPath(strPlayPath);
        printf("connection:[%d] publish, streamID:[%d] playpath:[%s] \n", conn->connId(), nInputStreamID, strPlayPath.c_str());

        // 检查streamID的有效性
        if (!conn->isValidStreamId(nInputStreamID))
        {
            printf("connection:[%d] publish, streamID:[%d] invalid! \n", conn->connId(), nInputStreamID);
            return -1;
        }

        conn->setStreamType(ClientConnection::Publish);
//        // 连接与节目 建立双向关联
//        pConn->setStreamType(CConnection::Publish);
//        pConn->bindPublishPlayPath(nInputStreamID, strPlayPath);
//        g_Apps.getApp(pConn->getAppName())->getPlayPath(strPlayPath)->setPublishConn(pConn->ConnID());

        if (!sendPublishStatus(conn, nInputStreamID))
            return -1;
    } else if (AVMATCH(&method, &av_play)) {
        AVal playpath;
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &playpath);
        int time = (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 4));

        std::string strPlayPath(playpath.av_val, playpath.av_len);
        //设置要播放视频的名字
        conn->setVideoPath(strPlayPath);
        printf("connection:[%d] play, streamID:[%d] playpath:[%s] time:[%d] \n", conn->connId(), nInputStreamID, strPlayPath.c_str(), time);

        // 检查streamID的有效性
        if (!conn->isValidStreamId(nInputStreamID))
        {
            printf("connection:[%d] play, streamID:[%d] invalid! \n", conn->connId(), nInputStreamID);
            return -1;
        }

        conn->setStreamType(ClientConnection::Play);
        // 连接与节目 建立双向关联
//        pConn->setStreamType(CConnection::Play);
//        pConn->bindPlayPlayPath(nInputStreamID, strPlayPath);
//        g_Apps.getApp(pConn->getAppName())->getPlayPath(strPlayPath, true)->addPlayConn(pConn->ConnID());

        if (!sendPlayStreamBegin(conn, nInputStreamID))
            return -1;

        if (!sendPlayStatus(conn, nInputStreamID))
            return -1;
    } else if (AVMATCH(&method, &av_FCUnpublish)) {
        AVal playpath;
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &playpath);

        std::string strPlayPath(playpath.av_val, playpath.av_len);
        printf("connection:[%d] FCUnpublish, playpath:[%s] \n", conn->connId(), strPlayPath.c_str());
        conn->setUnPublishFlag(true);

     //   g_Apps.getApp(pConn->getAppName())->getPlayPath(strPlayPath, true)->setEOF();
    } else if (AVMATCH(&method, &av_deleteStream)) {
        int nStreamID = (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 3));
        printf("connection:[%d] deleteStream, streamID:[%d] \n",conn->connId(), nStreamID);

        // 连接与节目 解除双向关联

//        std::string strPlayPath = pConn->getPublishPlayPath(nStreamID);
//        if (strPlayPath != "")
//        {
//            pConn->unbindPublishPlayPath(nStreamID);
//            g_Apps.getApp(pConn->getAppName())->getPlayPath(strPlayPath, true)->unsetPublishConn();
//        }

//        strPlayPath = pConn->getPlayPlayPath(nStreamID);
//        if (strPlayPath != "")
//        {
//            pConn->unbindPlayPlayPath(nStreamID);
//            g_Apps.getApp(pConn->getAppName())->getPlayPath(strPlayPath)->delPlayConn(pConn->ConnID());
//        }
    }

    AMF_Reset(&obj);
    return 0;
}


//写FLV-TAG
void RtmpServer::writeFlvTag(uint8_t tagType, uint32_t tagSize, uint32_t bodySize, uint32_t timestamp, char *body, FILE* flvFile) {
    unsigned char *pBodySize = (unsigned char *) &bodySize;
    unsigned char *pTimestamp = (unsigned char *) &timestamp;
    unsigned char *pTagSize = (unsigned char *) &tagSize;
    const unsigned char tagHeader[] = {
        tagType, //TAG Type，0x08表示音频，0x09表示视频，0x12表示脚本
        *(pBodySize + 2), *(pBodySize + 1), *pBodySize, //Body Size，按字节拷贝bodySize
        *(pTimestamp + 2), *(pTimestamp + 1), *pTimestamp, //Timestamp，按字节拷贝timestamp
        0x00, //Timestamp Extended，时间戳扩展
        0x00, 0x00, 0x00 //StreamID，永远为0
    };
    const unsigned char tagSizeBytes[] = {
        *(pTagSize + 3), *(pTagSize + 2), *(pTagSize + 1), *pTagSize
    };
    fwrite(tagHeader, 11, 1, flvFile);
    fwrite(body, bodySize, 1, flvFile);
    fwrite(tagSizeBytes, 4, 1, flvFile);
    fflush(flvFile);
}

bool RtmpServer::dispatch(std::shared_ptr<ClientConnection> conn, RTMPPacket *pPacket, FILE *pFile)
{
    uint32_t bodySize = pPacket->m_nBodySize;
    uint32_t tagSize = pPacket->m_nBodySize + 11;
    uint32_t timeStamp = pPacket->m_nTimeStamp;
    char* body = pPacket->m_body;

    switch(pPacket->m_packetType) {
        case 0x01:
            {
                if (pPacket->m_nBodySize >= 4)
                {
                    conn->rtmp()->m_inChunkSize = AMF_DecodeInt32(pPacket->m_body);
                    printf("connection:[%d] received: chunk size change to %d \n", conn->connId(), conn->rtmp()->m_inChunkSize);
                }
        }
        break;

    case 0x04:
        {
        }
        break;

    case 0x05:
        {
            if (pPacket->m_nBodySize >= 4)
            {
                int nWindowAckSize = AMF_DecodeInt32(pPacket->m_body);
                printf("connection:[%d] received: window ack size change to %d \n", conn->connId(), nWindowAckSize);
            }
        }
        break;

    case 0x06:
        {
            if (pPacket->m_nBodySize >= 4)
            {
                int nOutputBW = AMF_DecodeInt32(pPacket->m_body);
                printf("connection:[%d] received: output bw change to %d \n", conn->connId(), nOutputBW);
            }
            if (pPacket->m_nBodySize >= 5)
            {
                int nOutputBW2 = pPacket->m_body[4];
                printf("connection:[%d] received: output bw2 change to %d \n", conn->connId(), nOutputBW2);
            }
        }
        break;
        case 0x08:   //音频
            writeFlvTag(0x08, tagSize, bodySize, timeStamp, body, pFile);
            break;
        case 0x09:    //视频
            writeFlvTag(0x09, tagSize, bodySize, timeStamp, body, pFile);
            break;
        case 0x12:   //脚本信息
            writeFlvTag(0x12, tagSize, bodySize, timeStamp, body, pFile);
            break;
        case 0x14:
                //处理远程调用
            if (HandleInvoke(conn, pPacket) < 0) return false;
            break;
    }
    return true;
}

// 发送应答窗口大小报文
bool RtmpServer::sendWindowAckSize(std::shared_ptr<ClientConnection> pConn)
{
    char sBuf[256] = {0};
    char* pEnd = sBuf + sizeof(sBuf);

    RTMPPacket packet;
    packet.m_nChannel = 0x02;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet.m_packetType = 0x05;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = sBuf + RTMP_MAX_HEADER_SIZE;

    AMF_EncodeInt32(packet.m_body, pEnd, 5000000);
    packet.m_nBodySize = 4;

    if (!RTMP_SendPacket(pConn->rtmp(), &packet, FALSE))
    {
        printf("connection:[%d] send packet for set window ack size failed! \n", pConn->connId());
        return false;
    }

    return true;
}

// 发送设置对端输出带宽报文
bool RtmpServer::sendPeerOutputBandWide(std::shared_ptr<ClientConnection> pConn)
{
    char sBuf[256] = {0};
    char* pEnd = sBuf + sizeof(sBuf);

    RTMPPacket packet;
    packet.m_nChannel = 0x02;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet.m_packetType = 0x06;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = sBuf + RTMP_MAX_HEADER_SIZE;

    AMF_EncodeInt32(packet.m_body, pEnd, 5000000);
    packet.m_body[4] = 2;
    packet.m_nBodySize = 5;

    if (!RTMP_SendPacket(pConn->rtmp(), &packet, FALSE))
    {
        printf("connection:[%d] send packet for set peer output bandwide size failed! \n", pConn->connId());
        return false;
    }

    return true;
}

// 发送设置输出块大小报文
bool RtmpServer::sendOutputChunkSize(std::shared_ptr<ClientConnection> pConn)
{
    pConn->rtmp()->m_outChunkSize = 4096;

    char sBuf[256] = {0};
    char* pEnd = sBuf + sizeof(sBuf);

    RTMPPacket packet;
    packet.m_nChannel = 0x02;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet.m_packetType = 0x01;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = sBuf + RTMP_MAX_HEADER_SIZE;

    AMF_EncodeInt32(packet.m_body, pEnd, 4096);
    packet.m_nBodySize = 4;

    if (!RTMP_SendPacket(pConn->rtmp(), &packet, FALSE))
    {
        printf("connection:[%d] send packet for set chunk size failed! \n", pConn->connId());
        return false;
    }

    return true;
}

// 发送连接响应报文
bool RtmpServer::sendConnectResult(std::shared_ptr<ClientConnection> pConn, int nOperateID)
{
    char sBuf[256] = {0};
    char* pEnd = sBuf + sizeof(sBuf);

    RTMPPacket packet;
    packet.m_nChannel = 0x03;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet.m_packetType = 0x14;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = sBuf + RTMP_MAX_HEADER_SIZE;

    char* pEnc = packet.m_body;
    pEnc = AMF_EncodeString(pEnc, pEnd, &av__result);
    pEnc = AMF_EncodeNumber(pEnc, pEnd, nOperateID);

    AMFObject obj1 = {0, NULL};

    AMFObjectProperty fmsVer;
    fmsVer.p_name = makeAVal("fmsVer");
    fmsVer.p_type = AMF_STRING;
    fmsVer.p_vu.p_aval = makeAVal("FMS/3,0,1,123");
    AMF_AddProp(&obj1, &fmsVer);

    AMFObjectProperty capabilities;
    capabilities.p_name = makeAVal("capabilities");
    capabilities.p_type = AMF_NUMBER;
    capabilities.p_vu.p_number = 31;
    AMF_AddProp(&obj1, &capabilities);

    pEnc = AMF_Encode(&obj1, pEnc, pEnd);

    AMFObject obj2 = {0, NULL};

    AMFObjectProperty level;
    level.p_name = makeAVal("level");
    level.p_type = AMF_STRING;
    level.p_vu.p_aval = makeAVal("status");
    AMF_AddProp(&obj2, &level);

    AMFObjectProperty code;
    code.p_name = makeAVal("code");
    code.p_type = AMF_STRING;
    code.p_vu.p_aval = makeAVal("NetConnection.Connect.Success");
    AMF_AddProp(&obj2, &code);

    pEnc = AMF_Encode(&obj2, pEnc, pEnd);

    packet.m_nBodySize = pEnc - packet.m_body;

    if (!RTMP_SendPacket(pConn->rtmp(), &packet, FALSE))
    {
        printf("connection:[%d] send packet for connect _result failed! \n", pConn->connId());
        return false;
    }

    return true;
}

// 发送创建流响应报文
bool RtmpServer::sendCreateStreamResult(std::shared_ptr<ClientConnection> pConn, int nOperateID, uint32_t nStreamID)
{
    char sBuf[256] = {0};
    char* pEnd = sBuf + sizeof(sBuf);

    RTMPPacket packet;
    packet.m_nChannel = 0x03;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet.m_packetType = 0x14;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = sBuf + RTMP_MAX_HEADER_SIZE;

    char* pEnc = packet.m_body;
    pEnc = AMF_EncodeString(pEnc, pEnd, &av__result);
    pEnc = AMF_EncodeNumber(pEnc, pEnd, nOperateID);
    *pEnc++ = AMF_NULL;
    pEnc = AMF_EncodeNumber(pEnc, pEnd, nStreamID);

    packet.m_nBodySize = pEnc - packet.m_body;

    if (!RTMP_SendPacket(pConn->rtmp(), &packet, FALSE))
    {
        printf("connection:[%d] send packet for createStream _result failed! \n", pConn->connId());
        return false;
    }

//    std::cout << "createstream success\n";
    return true;
}

// 发送推流状态响应报文
bool RtmpServer::sendPublishStatus(std::shared_ptr<ClientConnection> pConn, int nInputStreamID)
{
    char sBuf[256] = {0};
    char* pEnd = sBuf + sizeof(sBuf);

    RTMPPacket packet;
    packet.m_nChannel = 0x05;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet.m_packetType = 0x14;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = nInputStreamID;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = sBuf + RTMP_MAX_HEADER_SIZE;

    char* pEnc = packet.m_body;
    pEnc = AMF_EncodeString(pEnc, pEnd, &av_onStatus);
    pEnc = AMF_EncodeNumber(pEnc, pEnd, 0);
    *pEnc++ = AMF_NULL;

    AMFObject obj2 = {0, NULL};

    AMFObjectProperty level;
    level.p_name = makeAVal("level");
    level.p_type = AMF_STRING;
    level.p_vu.p_aval = makeAVal("status");
    AMF_AddProp(&obj2, &level);

    AMFObjectProperty code;
    code.p_name = makeAVal("code");
    code.p_type = AMF_STRING;
    code.p_vu.p_aval = makeAVal("NetStream.Publish.Start");
    AMF_AddProp(&obj2, &code);

    pEnc = AMF_Encode(&obj2, pEnc, pEnd);

    packet.m_nBodySize = pEnc - packet.m_body;

    if (!RTMP_SendPacket(pConn->rtmp(), &packet, FALSE))
    {
        printf("connection:[%d] send packet for publish onStatus failed! \n", pConn->connId());
        return false;
    }

    return true;
}

// 发送推流错误响应报文
bool RtmpServer::sendPublishError(std::shared_ptr<ClientConnection> pConn, int nInputStreamID)
{
    char sBuf[256] = {0};
    char* pEnd = sBuf + sizeof(sBuf);

    RTMPPacket packet;
    packet.m_nChannel = 0x05;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet.m_packetType = 0x14;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = nInputStreamID;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = sBuf + RTMP_MAX_HEADER_SIZE;

    char* pEnc = packet.m_body;
    pEnc = AMF_EncodeString(pEnc, pEnd, &av_onStatus);
    pEnc = AMF_EncodeNumber(pEnc, pEnd, 0);
    *pEnc++ = AMF_NULL;

    AMFObject obj2 = {0, NULL};

    AMFObjectProperty level;
    level.p_name = makeAVal("level");
    level.p_type = AMF_STRING;
    level.p_vu.p_aval = makeAVal("error");
    AMF_AddProp(&obj2, &level);

    AMFObjectProperty code;
    code.p_name = makeAVal("code");
    code.p_type = AMF_STRING;
    code.p_vu.p_aval = makeAVal("NetStream.Publish.BadName");
    AMF_AddProp(&obj2, &code);

    AMFObjectProperty description;
    description.p_name = makeAVal("description");
    description.p_type = AMF_STRING;
    description.p_vu.p_aval = makeAVal("Already publishing");
    AMF_AddProp(&obj2, &description);

    pEnc = AMF_Encode(&obj2, pEnc, pEnd);

    packet.m_nBodySize = pEnc - packet.m_body;

    if (!RTMP_SendPacket(pConn->rtmp(), &packet, FALSE))
    {
        printf("connection:[%d] send packet for publish onStatus failed! \n", pConn->connId());
        return false;
    }

    return true;
}

// 发送拉流事件报文
bool RtmpServer::sendPlayStreamBegin(std::shared_ptr<ClientConnection> pConn, int nInputStreamID)
{
    char sBuf[256] = {0};
    char* pEnd = sBuf + sizeof(sBuf);

    RTMPPacket packet;
    packet.m_nChannel = 0x02;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet.m_packetType = 0x04;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = sBuf + RTMP_MAX_HEADER_SIZE;

    char* pEnc = packet.m_body;
    pEnc = AMF_EncodeInt16(pEnc, pEnd, 0);
    pEnc = AMF_EncodeInt32(pEnc, pEnd, nInputStreamID);

    packet.m_nBodySize = pEnc - packet.m_body;

    if (!RTMP_SendPacket(pConn->rtmp(), &packet, FALSE))
    {
        printf("connection:[%d] send packet for play event failed! \n", pConn->connId());
        return false;
    }

    return true;
}

// 发送拉流状态响应报文
bool RtmpServer::sendPlayStatus(std::shared_ptr<ClientConnection> pConn, int nInputStreamID)
{
    char sBuf[256] = {0};
    char* pEnd = sBuf + sizeof(sBuf);

    RTMPPacket packet;
    packet.m_nChannel = 0x05;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet.m_packetType = 0x14;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = nInputStreamID;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = sBuf + RTMP_MAX_HEADER_SIZE;

    char* pEnc = packet.m_body;
    pEnc = AMF_EncodeString(pEnc, pEnd, &av_onStatus);
    pEnc = AMF_EncodeNumber(pEnc, pEnd, 0);
    *pEnc++ = AMF_NULL;

    AMFObject obj2 = {0, NULL};

    AMFObjectProperty level;
    level.p_name = makeAVal("level");
    level.p_type = AMF_STRING;
    level.p_vu.p_aval = makeAVal("status");
    AMF_AddProp(&obj2, &level);

    AMFObjectProperty code;
    code.p_name = makeAVal("code");
    code.p_type = AMF_STRING;
    code.p_vu.p_aval = makeAVal("NetStream.Play.Start");
    AMF_AddProp(&obj2, &code);

    pEnc = AMF_Encode(&obj2, pEnc, pEnd);

    packet.m_nBodySize = pEnc - packet.m_body;

    if (!RTMP_SendPacket(pConn->rtmp(), &packet, FALSE))
    {
        printf("connection:[%d] send packet for play onStatus failed! \n", pConn->connId());
        return false;
    }

    return true;
}

