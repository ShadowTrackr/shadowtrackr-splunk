APP ?= shadowtrackr
VERSION ?= 1.1.0

# Tools from the project venv, so it needn't be activated. Quoted, because the
# checkout path may contain spaces (make's own PATH lookup breaks on those).
VENV ?= $(CURDIR)/venv
PYTEST = "$(VENV)/bin/pytest"
UCC_GEN = "$(VENV)/bin/ucc-gen"
APPINSPECT = "$(VENV)/bin/splunk-appinspect"

.PHONY: build package test test-bundled deploy up down restart logs inspect index mock devlogs dashboards savedsearches hec

build:
	# Tests import package/bin; never ship their __pycache__ (AppInspect rejects .pyc files).
	find package -name __pycache__ -type d -prune -exec rm -rf {} +
	$(UCC_GEN) build --ta-version $(VERSION) --python-binary-name "$(VENV)/bin/python3"

# The tarball to upload to Splunkbase, checked by AppInspect the way Splunkbase does.
package: build
	mkdir -p dist
	$(UCC_GEN) package --path "output/$(APP)" -o dist
	$(APPINSPECT) inspect "dist/$(APP)-$(VERSION).tar.gz" --included-tags cloud

test:
	$(PYTEST) tests/

# Run the tests against the libraries bundled in the add-on (urllib3 1.26).
test-bundled: build
	PYTHONPATH="output/$(APP)/lib" $(PYTEST) tests/ -p no:cacheprovider

deploy: build
	mkdir -p splunk-dev/apps/$(APP)
	# Keep local/ (accounts, encrypted credentials, inputs) created in Splunk Web.
	rsync -a --delete --exclude local/ --exclude metadata/local.meta "output/$(APP)/" "splunk-dev/apps/$(APP)/"

up:
	docker compose up -d

down:
	docker compose down

restart: deploy
	docker compose exec -u splunk splunk /opt/splunk/bin/splunk restart

logs:
	docker compose exec -u splunk splunk tail -n 100 -f /opt/splunk/var/log/splunk/splunkd.log

inspect: build
	$(APPINSPECT) inspect "output/$(APP)" --included-tags cloud

# Create the shadowtrackr index in the dev Splunk container.
index:
	docker compose exec -u splunk splunk sh -c '/opt/splunk/bin/splunk add index shadowtrackr -auth "admin:$$SPLUNK_PASSWORD"'

# Mock ShadowTrackr API on port 8081. From the Splunk container use
# http://host.docker.internal:8081/api/v4 with API key mock-api-key-0000000000.
mock:
	python3 mock_api/server.py --shift-to-now

# Synthetic firewall/proxy/auth/IDS logs in the dev Splunk, for Asset 360.
devlogs:
	python3 -I tools/gen_dev_logs.py

# Regenerate the Dashboard Studio views from tools/gen_dashboards.py.
dashboards:
	python3 -I tools/gen_dashboards.py

# Regenerate the detections (savedsearches.conf) from tools/gen_savedsearches.py.
savedsearches:
	python3 -I tools/gen_savedsearches.py

# Send synthetic alert webhook deliveries through HEC and check the parsing.
hec:
	python3 -I tools/send_webhook_test.py
