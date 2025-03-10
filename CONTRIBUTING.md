# Contributing

Contributing is relatively easy, you just need to follow the steps carefully and you will be up and running with a development server in less than 5 minutes.

## Requirements

- Bun
- Golang v1.23.2 and above
- Git
- Docker
- Make (not required but it will make your life easier)

## Cloning the repository

You firstly need to clone the repository with:

```sh
git clone https://github.com/steveiliop56/tinyauth
cd tinyauth
```

## Install requirements

To install the requirements simply run:

```sh
make requirements
```

It will download all the node packages required by the frontend as well as all the go requirements.

## Developing locally

In order to develop the app you need to firstly compile the frontend and then the go app. To avoid running the same commands over and over again you can just run:

```sh
make run
```

This is the equivalent of `go run main.go`, if you would like to build a binary run:

```sh
make build
```

To avoid rebuilding the frontend every time you can run:

```sh
make run-no-web
```

And:

```sh
make build-no-web
```

For these commands to succeed you must have built the frontend at least once.

> [!WARNING]
> Make sure you have set the environment variables when running outside of docker else the app will fail.

## Developing in docker

My recommended development method is docker so I can test that both my image works and that the app responds correctly to traefik. In my setup I have set these two DNS records in my DNS server:

```
*.dev.example.com -> 127.0.0.1
dev.example.com -> 127.0.0.1
```

Then I can just make sure the domains are correct in the example docker compose file and do:

```sh
docker compose -f docker-compose.dev.yml up --build
```

> [!WARNING]
> I would recommend copying the example `docker-compose.dev.yml` into a `docker-compose.test.yml` file, so as you don't accidentally commit any sensitive information.
