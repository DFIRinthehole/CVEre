.PHONY: test demo html clean

test:
	python3 -m unittest discover -s tests -v

demo:            ## look up a CVE end to end
	python3 -m cvere CVE-2021-44228

html:            ## regenerate the demo reports from the example scan
	python3 -m cvere examples/scan.xml --top 4 -q \
		--html reports/scan-report.html --md reports/scan-report.md --json reports/scan-report.json

clean:
	rm -rf __pycache__ */__pycache__ build dist *.egg-info .venv
