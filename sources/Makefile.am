libdir           = @plugindir@
lib_LTLIBRARIES  = torchat.la

torchat_la_CFLAGS  = $(BITLBEE_CFLAGS) $(GLIB_CFLAGS) -Wall
torchat_la_LDFLAGS = -module -avoid-version $(GLIB_LIBS)
torchat_la_SOURCES = torchat.c
