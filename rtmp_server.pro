TEMPLATE = app
CONFIG += console c++20
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        clientconnection.cpp \
        clientconnmanager.cpp \
        main.cpp \
        rtmpserver.cpp \
    threadpool.cpp

HEADERS += \
    clientconnection.h \
    clientconnmanager.h \
    rtmpserver.h \
    threadpool.h

unix|win32: LIBS += -lrtmp
unix|win32: LIBS += -lpthread
