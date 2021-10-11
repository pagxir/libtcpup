LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := client.udp
LOCAL_SRC_FILES := client.cpp tcp_listen.cpp tcp_channel.cpp 

LOCAL_SRC_FILES +=  cc_hybla.cpp cc_hybla0.cpp cc_newreno.cpp cc_cubic.cpp cc.cpp cc_htcp.cpp cc_vegas.cpp h_ertt.cpp cc_vegasab.cpp 
LOCAL_SRC_FILES += libtx.a socket.cpp rgnbuf.cpp tcp_debug.cpp \
		  tcp_input.cpp tcp_output.cpp tcp_timer.cpp tcp_subr.cpp \
		  tcp_usrreq.cpp tcp_sack.cpp tcp_crypt.cpp client_track.cpp router.cpp tcp_device.cpp \
		  tcp_device_icmp.cpp tcp_device_icmp_user.cpp  ifdev_stdio.cpp if_dev.cpp

LOCAL_CFLAGS += -I$(LOCAL_PATH)/libtx/include -fPIC
LOCAL_LDFLAGS += 
LOCAL_STATIC_LIBRARIES := libtx
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := server.udp
LOCAL_SRC_FILES := server.cpp pstcp_channel.cpp pstcp_listen.cpp dns_txasync.cpp dns_forward.cpp

LOCAL_SRC_FILES +=  cc_hybla.cpp cc_hybla0.cpp cc_newreno.cpp cc_cubic.cpp cc.cpp cc_htcp.cpp cc_vegas.cpp h_ertt.cpp cc_vegasab.cpp 
LOCAL_SRC_FILES += libtx.a socket.cpp rgnbuf.cpp tcp_debug.cpp \
		  tcp_input.cpp tcp_output.cpp tcp_timer.cpp tcp_subr.cpp \
		  tcp_usrreq.cpp tcp_sack.cpp tcp_crypt.cpp client_track.cpp router.cpp tcp_device.cpp \
		  tcp_device_icmp.cpp tcp_device_icmp_user.cpp  ifdev_stdio.cpp if_dev.cpp

LOCAL_CFLAGS += -I$(LOCAL_PATH)/libtx/include -fPIC
LOCAL_LDFLAGS += 
LOCAL_STATIC_LIBRARIES := libtx
include $(BUILD_EXECUTABLE)
