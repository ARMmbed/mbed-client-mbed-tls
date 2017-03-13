#
# Makefile.test for mbed-client-mbed-tls unit tests
#


# List of subdirectories to build
TEST_FOLDER := ./test/
# List of unit test directories for libraries
UNITTESTS := $(sort $(dir $(wildcard $(TEST_FOLDER)*/unittest/*)))
TESTDIRS := $(UNITTESTS:%=build-%)
CLEANTESTDIRS := $(UNITTESTS:%=clean-%)
COVERAGEFILE := ./lcov/coverage.info

.PHONY: clone
clone:
	@rm -rf ./test_modules
	@mkdir -p test_modules
	@git clone --depth 1 git@github.com:ARMmbed/mbed-os.git ./test_modules/mbed-os
	@git clone --depth 1 git@github.com:ARMmbed/mbed-trace.git ./test_modules/mbed-trace
	@git clone --depth 1 git@github.com:ARMmbed/nanostack-libservice.git ./test_modules/nanostack-libservice
	@git clone --depth 1 git@github.com:ARMmbed/mbed-client-c.git ./test_modules/mbed-client-c
	@git clone --depth 1 git@github.com:ARMmbed/mbed-client.git ./test_modules/mbed-client
	@git clone --depth 1 git@github.com:ARMmbed/mbed-client-classic.git ./test_modules/mbed-client-classic
	@git clone --depth 1 git@github.com:ARMmbed/mbedtls.git ./test_modules/mbedtls
	@git clone --depth 1 git@github.com:ARMmbed/mbed-client-pal.git ./test_modules/mbed-client-pal

.PHONY: test
test: $(TESTDIRS)
	@rm -rf ./lcov
	@rm -rf ./coverage
	@mkdir -p lcov
	@mkdir -p lcov/results
	@mkdir coverage
	@find ./test -name '*.xml' | xargs cp -t ./lcov/results/
	@rm -f lcov/index.xml
	@./xsl_script.sh
	@cp junit_xsl.xslt lcov/.
	@xsltproc -o lcov/testresults.html lcov/junit_xsl.xslt lcov/index.xml
	@rm -f lcov/junit_xsl.xslt
	@rm -f lcov/index.xml
	@find ./ -name '*.gcno' | xargs cp --backup=numbered -t ./coverage/
	@find ./ -name '*.gcda' | xargs cp --backup=numbered -t ./coverage/
	@gcovr --object-directory ./coverage  --exclude-unreachable-branches -e '.*/builds/.*' -e '.*/test/.*' -e '.*/test_modules/.*' -e '.*/stubs/.*' -e '.*/mbed-client-classic/.*' -e '.*/usr/.*' -x -o ./lcov/gcovr.xml
	@lcov -d test/. -c -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/usr*" -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/test*" -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/mbed-client-libservice*" -o $(COVERAGEFILE)
	@genhtml -q $(COVERAGEFILE) --show-details --output-directory lcov/html
	@echo mbed-client-classic module unit tests built

$(TESTDIRS):
	@make -C $(@:build-%=%)

$(CLEANDIRS):
	@make -C $(@:clean-%=%) clean

$(CLEANTESTDIRS):
	@make -C $(@:clean-%=%) clean

# Extend default clean rule
clean: clean-extra

clean-extra: $(CLEANDIRS) \
$(CLEANTESTDIRS)
