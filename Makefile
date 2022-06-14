BASE_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
OS_TYPE := $(shell uname -s)
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
MKDIR_P = mkdir -p

.PHONY: all
all: check test

.PHONY: check
check: psalm phpcs bom

.PHONY: bom
bom:
	@rm -f build/reports/bom.json
	@mkdir -p build/reports
	composer make-bom --output-format=JSON --output-file=build/reports/bom.json --no-interaction

.PHONY: psalm
psalm:
	./vendor/bin/psalm $(PSALM_ARGS)

.PHONY: phpcs
phpcs:
	./vendor/bin/phpcs --standard="./phpcs.xml" --colors -p -s .

.PHONY: test
test:
	@./vendor/bin/phpunit
