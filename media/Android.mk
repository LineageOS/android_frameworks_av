LOCAL_PATH := $(call my-dir)

$(eval $(call declare-1p-copy-files,frameworks/av/media/libeffects,audio_effects.conf))
$(eval $(call declare-1p-copy-files,frameworks/av/media/libeffects,audio_effects.xml))
$(eval $(call declare-1p-copy-files,frameworks/av/media/libstagefright,))
