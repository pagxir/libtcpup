LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := stun_helo
LOCAL_SRC_FILES := stun_helo.cpp
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie
include $(BUILD_EXECUTABLE)

include $(LOCAL_PATH)/../libtx/Android.mk
include $(LOCAL_PATH)/../Android.mk

