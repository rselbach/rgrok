set dotenv-load

BINARY := "rgrok"
PREFIX := "/usr/local"
BINDIR := PREFIX + "/bin"
SYSTEMD_DIR := "/etc/systemd/system"
CONFIG_DIR := "/etc/rgrok"

default:
	@just --list

build:
	go build -o ./bin/{{BINARY}} ./cmd/rgrok

test:
	go test ./...

install-binary: build
	sudo install -d -m 0755 {{BINDIR}}
	sudo install -m 0755 ./bin/{{BINARY}} {{BINDIR}}/{{BINARY}}

install-systemd:
	sudo install -d -m 0755 {{SYSTEMD_DIR}}
	sudo install -m 0644 deploy/rgrok-server.service {{SYSTEMD_DIR}}/rgrok-server.service
	sudo install -d -m 0755 {{CONFIG_DIR}}
	if [ ! -f {{CONFIG_DIR}}/rgrok-server.env ]; then sudo install -m 0600 deploy/rgrok-server.env {{CONFIG_DIR}}/rgrok-server.env; else echo "{{CONFIG_DIR}}/rgrok-server.env already exists; leaving it unchanged"; fi
	sudo install -d -o rgrok -g rgrok -m 0750 /var/lib/rgrok
	sudo systemctl daemon-reload

install: install-binary install-systemd

enable-server:
	sudo systemctl enable rgrok-server.service

start-server:
	sudo systemctl start rgrok-server.service

restart-server:
	sudo systemctl restart rgrok-server.service

status-server:
	systemctl status rgrok-server.service
