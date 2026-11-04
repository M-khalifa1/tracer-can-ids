CC     = gcc
CFLAGS = -Wall -Wextra -O2 -I.
LIBS   = -lm
ENGINE = tracer_ids.c
HDR    = tracer_ids.h sha256.h

.PHONY: all test clean
all: ids_daemon signed_sender ids_runner bench_hmac test_v3 test
	@echo "build complete."

ids_daemon:    ids_daemon.c    $(ENGINE) $(HDR)
	$(CC) $(CFLAGS) ids_daemon.c    $(ENGINE) $(LIBS) -o $@
signed_sender: signed_sender.c $(ENGINE) $(HDR)
	$(CC) $(CFLAGS) signed_sender.c $(ENGINE) $(LIBS) -o $@
ids_runner:    ids_runner.c    $(ENGINE) $(HDR)
	$(CC) $(CFLAGS) ids_runner.c    $(ENGINE) $(LIBS) -o $@
bench_hmac:    bench_hmac.c    $(ENGINE) $(HDR)
	$(CC) $(CFLAGS) bench_hmac.c    $(ENGINE) $(LIBS) -o $@
test_v3:       test_v3.c       $(ENGINE) $(HDR)
	$(CC) $(CFLAGS) test_v3.c       $(ENGINE) $(LIBS) -o $@

test: test_v3
	./test_v3

clean:
	rm -f ids_daemon signed_sender ids_runner bench_hmac test_v3
