# Contributing

Contributing is relatively easy.

## Requirements

- Bun
- Golang v1.23.2 and above
- Git
- Docker

## Cloning the repository

You firstly need to clone the repository with:

```sh
git clone https://github.com/steveiliop56/tinyauth
cd tinyauth
```

## Install requirements

Now it's time to install the requirements, firstly the Go ones:

```sh
go mod download
```

And now the site ones:

```sh
cd site
bun i
```

## Developing locally

In order to develop the app locally you need to build the frontend and copy it to the assets folder in order for Go to embed it and host it. In order to build the frontend run:

```sh
cd site
bun run build
cd ..
```

Copy it to the assets folder:

```sh
rm -rf internal/assets/dist
cp -r site/dist internal/assets/dist
```

Finally either run the app with:

```sh
go run main.go
```

Or build it with:

```sh
go build
```

> [!WARNING]
> Make sure you have set the environment variables when running outside of docker else the app will fail.

## Developing in docker

My recommended development method is docker so I can test that both my image works and that the app responds correctly to traefik. In my setup I have set these two DNS records in my DNS server:

```
*.dev.local -> 127.0.0.1
dev.local -> 127.0.0.1
```

Then I can just make sure the domains are correct in the example docker compose file and do:

```sh
docker compose -f docker-compose.dev.yml up --build
```
