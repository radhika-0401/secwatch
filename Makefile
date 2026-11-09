.PHONY: install test lint sast demo docker clean

install:
	pip install -e ".[dev]"

test:
	pytest --cov=secwatch --cov-report=term-missing

lint:
	ruff check .

sast:
	bandit -c pyproject.toml -r secwatch

demo:
	secwatch detect --auth sample_data/auth.log --web sample_data/access.log \
		--cloudtrail sample_data/cloudtrail.json --year 2026 -o reports -f json,md,html,sarif
	secwatch harden --root sample_data/linux_root -o reports
	secwatch iac --plan sample_data/tfplan.json -o reports -f json,md,html,sarif

docker:
	docker build -t secwatch:latest .
	docker run --rm -v "$$PWD:/work" secwatch:latest iac --plan sample_data/tfplan.json -o reports

clean:
	rm -rf reports .pytest_cache .ruff_cache .coverage htmlcov *.egg-info
