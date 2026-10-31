APP ?= shadowtrackr

.PHONY: build test deploy up down restart logs inspect

build:
	ucc-gen build

test:
	pytest tests/

deploy: build
	mkdir -p splunk-dev/apps/$(APP)
	rsync -a --delete "output/$(APP)/" "splunk-dev/apps/$(APP)/"

up:
	docker compose up -d

down:
	docker compose down

restart: deploy
	docker compose exec splunk /opt/splunk/bin/splunk restart

logs:
	docker compose exec splunk tail -n 100 -f /opt/splunk/var/log/splunk/splunkd.log

inspect: build
	splunk-appinspect inspect "output/$(APP)" --included-tags cloud