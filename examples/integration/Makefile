run:
	docker compose down
	docker compose up -d
	docker compose build client
	docker compose exec -T sshportal /bin/sshportal healthcheck --wait --quiet
	docker compose run client /integration/_client.sh
	docker compose down

build:
	docker compose build
