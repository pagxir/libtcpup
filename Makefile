MODULE := tcpup
THIS_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifneq ($(TARGET),)
CC := $(TARGET)-gcc
LD := $(TARGET)-ld
AR := $(TARGET)-ar
CXX := $(TARGET)-g++
endif

LOCAL_TARGETS := txcat libtx.a
LOCAL_CXXFLAGS := -I$(THIS_PATH)/libtx/include -I$(THIS_PATH)
LOCAL_CFLAGS := $(LOCAL_CXXFLAGS)
LOCAL_LDLIBS := -lstdc++

ifeq ($(BUILD_TARGET), )
BUILD_TARGET := $(shell uname)
endif

ifeq ($(BUILD_TARGET), mingw)
LOCAL_LDFLAGS += -static
LOCAL_LDLIBS += -lws2_32
endif

ifeq ($(BUILD_TARGET), Linux)
LOCAL_LDLIBS += -lrt
endif

LOCAL_CFLAGS += -g -Wall -Wno-sign-compare -I.
LOCAL_CXXFLAGS += -g -Wall -Wno-sign-compare -I.

VPATH := $(THIS_PATH)/libtx:$(THIS_PATH)

TARGETS = server.udp server.icm client.udp client.raw 

ifeq ($(BUILD_TARGET), mingw)
LOCAL_LDFLAGS += -static
LOCAL_LDLIBS += -lws2_32
TARGETS += server.srv
endif

ifeq ($(BUILD_TARGET), Linux)
LDLIBS += -lrt -lpthread
endif

all: $(TARGETS)

SRV_OBJ = server.o pstcp_channel.o pstcp_listen.o dns_txasync.o dns_forward.o
CLT_OBJ = client.o tcp_listen.o tcp_channel.o
USRV_OBJ = server.o pstcp_listen.o pstcp_http.o 
MAIN_OBJ = pstcp_main.o pstcp_listen.o pstcp_http.o 
NCAT_OBJ = netcat.o pstcp_listen.o pstcp_netcat.o
CC_OBJS =  cc_hybla.o cc_hybla0.o cc_newreno.o cc_cubic.o cc.o cc_htcp.o cc_vegas.o h_ertt.o
CC_OBJS +=  cc_vegasab.o 
LOCAL_OBJECTS := libtx.a socket.o rgnbuf.o tcp_debug.o \
		  tcp_input.o tcp_output.o tcp_timer.o tcp_subr.o \
		  tcp_usrreq.o tcp_sack.o $(CC_OBJS) tcp_crypt.o

$(TARGETS): OBJECTS:=$(LOCAL_OBJECTS)

CFLAGS  := $(LOCAL_CFLAGS) $(CFLAGS)
CXXFLAGS := $(LOCAL_CXXFLAGS) $(CXXFLAGS)

LDLIBS   := $(LOCAL_LDLIBS) $(LDLIBS)
LDFLAGS  := $(LOCAL_LDFLAGS) $(LDFLAGS)

server.udp: $(SRV_OBJ) $(LOCAL_OBJECTS) tcp_device.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

server.icm: $(SRV_OBJ) $(LOCAL_OBJECTS) tcp_device_icmp.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

server.http: $(USRV_OBJ) $(LOCAL_OBJECTS) tcp_device.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

WINSRVOBJ = tcp_device.o server_srv.o pstcp_channel.o pstcp_listen.o dns_txasync.o winsrv.o dns_forward.o
server.srv: $(WINSRVOBJ) $(LOCAL_OBJECTS) 
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

client.udp: $(CLT_OBJ) $(LOCAL_OBJECTS) tcp_device.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

client.icm: $(CLT_OBJ) $(LOCAL_OBJECTS) tcp_device_icmp_user.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

client.raw: $(CLT_OBJ) $(LOCAL_OBJECTS) tcp_device_icmp.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

server_srv.o: server.cpp
	$(CXX) -c $(CXXFLAGS) -D_WINSRV_ $< -o server_srv.o 

tcp_device_icmp_user.o: tcp_device_icmp.o
	$(CXX) $(CXXFLAGS) -D_DNS_CLIENT_ -o tcp_device_icmp_user.o tcp_device_icmp.cpp

include $(THIS_PATH)/libtx/Makefile
