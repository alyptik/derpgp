#
# derpgp - derpgp
#
# AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
#		Santiago Torres <sangy@riseup.net>
#
# See LICENSE.md file for copyright and license details.

all:
	$(MAKE) $(TARGET) check
	# @$(CC) $(CFLAGS) bn.c ./tests/golden.c     -o ./build/test_golden
	# @$(CC) $(CFLAGS) bn.c ./tests/load_cmp.c   -o ./build/test_load_cmp
	# @$(CC) $(CFLAGS) bn.c ./tests/factorial.c  -o ./build/test_factorial
	# @$(CC) $(CFLAGS) bn.c ./tests/randomized.c -o ./build/test_random
	# @#$(CC) $(CFLAGS) bn.c ./tests/rsa.c        -o ./build/test_rsa

# user configuration
MKCFG := config.mk
# if previously built with `-fsanitize=address` we have to use `DEBUG` flags
OPT != test -f debug.mk
ifeq ($(.SHELLSTATUS), 0)
	OLVL = $(DEBUG)
endif
-include $(DEP) $(MKCFG)
.PHONY: all check clean debug dist install test uninstall $(MKALL)

debug:
	# debug indicator flag
	@touch debug.mk
	@rm -f $(TARGET)
	$(MAKE) $(TARGET) check

$(TARGET): %: $(OBJ)
	$(LD) $(LDFLAGS) $(OLVL) $(LIBS) $^ -o $@
$(BNTEST): %: %.c $(TAP).o
	$(CC) $(LDFLAGS) $(OLVL) $(LIBS) $(TAP).o $< -o $@
$(TEST): %: %.o $(TAP).o $(OBJ) $(BNTEST)
	$(LD) $(LDFLAGS) $(OLVL) $(LIBS) $(TAP).o $(<:t/test%=src/%) $< -o $@
$(PARSE): %: %.o $(TAP).o $(OBJ)
	$(LD) $(LDFLAGS) $(OLVL) $(LIBS) $(TAP).o $(filter-out src/$(TARGET).o,$(OBJ)) $< -o $@
%.d %.o: %.c
	$(CC) $(CFLAGS) $(OLVL) $(CPPFLAGS) -c $< -o $@

test check: $(TOBJ) $(TEST) $(PARSE) $(BNTEST)
	@echo ================================================================================
	@./t/golden
	@echo ================================================================================
	@./t/load_cmp
	@echo ================================================================================
	@python2 ./t/fact100.py
	@./t/factorial
	@echo ================================================================================
	@python2 ./t/test_old_errors.py
	@echo ================================================================================
	@#./t/rsa
	@#echo ================================================================================
	@python2 ./t/test_rand.py 1000
	@echo "=========="
	./t/testparse
	@echo "=========="
	./t/testpacket
	@echo "=========="
	./t/testpkcs
	@echo "=========="

clean:
	@echo "cleaning"
	@rm -fv $(DEP) $(TARGET) $(TEST) $(OBJ) $(TOBJ) $(TARGET).tar.gz debug.mk
install: $(TARGET)
	@echo "installing"
	@mkdir -pv $(DESTDIR)$(PREFIX)/$(BINDIR)
	@mkdir -pv $(DESTDIR)$(PREFIX)/$(MANDIR)
	install -c $(TARGET) $(DESTDIR)$(PREFIX)/$(BINDIR)
	install -c $(MANPAGE) $(DESTDIR)$(PREFIX)/$(MANDIR)
uninstall:
	@rm -fv $(DESTDIR)$(PREFIX)/$(BINDIR)/$(TARGET)
	@rm -fv $(DESTDIR)$(PREFIX)/$(MANDIR)/$(MANPAGE)
dist: clean
	@echo "creating dist tarball"
	@mkdir -pv $(TARGET)/
	@cp -Rv LICENSE.md Makefile README.md $(HDR) $(SRC) $(TSRC) $(MANPAGE) $(TARGET)/
	tar -czf $(TARGET).tar.gz $(TARGET)/
	@rm -rfv $(TARGET)/
