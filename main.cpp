#include <iostream>
#include "rtmpserver.h"

int main()
{
    RtmpServer server(20);
    server.start();
    return 0;
}
