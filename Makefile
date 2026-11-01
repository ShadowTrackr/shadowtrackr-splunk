APP ?= shadowtrackr
VERSION ?= 0.1.0

.PHONY: build test test-bundled deploy up down restart logs inspect index mock

build:
	# Tests import package/bin; never ship their __pycache__ (AppInspect rejects .pyc files).
	find package -name __pycache__ -type d -prune -exec rm -rf {} +
	ucc-gen build --ta-version $(VERSION)

test:
	pytest tests/

# Run the tests against the libraries bundled in the add-on (urllib3 1.26).
test-bundled: build
	PYTHONPATH="output/$(APP)/lib" pytest tests/ -p no:cacheprovider

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
	splunk-appinspect inspect "output/$(APP)" --included-tags cloud

# Create the shadowtrackr index in the dev Splunk container.
index:
	docker compose exec -u splunk splunk sh -c '/opt/splunk/bin/splunk add index shadowtrackr -auth "admin:$$SPLUNK_PASSWORD"'

# Mock ShadowTrackr API on port 8081. From the Splunk container use
# http://host.docker.internal:8081/api/v4 with API key mock-api-key-0000000000.
mock:
	python3 mock_api/server.py --shift-to-now
