# Contributing

Contributing is relatively easy, you just need to follow the steps below and you will be up and running with a development server in less than five minutes.

## Requirements

- Bun
- Golang v1.24.0+
- Git
- Docker

## Cloning the repository

You firstly need to clone the repository with:

```sh
git clone https://github.com/steveiliop56/tinyauth
cd tinyauth
```

## Initialize submodules

The project uses Git submodules for some dependencies, so you need to initialize them with:

```sh
git submodule init
git submodule update
```

## Install requirements

Although you will not need the requirements in your machine since the development will happen in Docker, I still recommend to install them because this way you will not have import errors. To install the Go requirements run:

```sh
go mod download
```

You also need to download the frontend dependencies, this can be done like so:

```sh
cd frontend/
bun install
```

## Apply patches

Some of the dependencies need to be patched in order to work correctly with the project, you can apply the patches by running:

```sh
git apply --directory paerser/ patches/nested_maps.diff
```

## Create your `.env` file

In order to configure the app you need to create an environment file, this can be done by copying the `.env.example` file to `.env` and modifying the environment variables to suit your needs.

## Developing

I have designed the development workflow to be entirely in Docker, this is because it will directly work with Traefik and you will not need to do any building in your host machine. The recommended development setup is to have a subdomain pointing to your machine like this:

```
*.dev.example.com -> 127.0.0.1
dev.example.com -> 127.0.0.1
```

> [!TIP]
> You can use [sslip.io](https://sslip.io) as a domain if you don't have one to develop with.

Then you can just make sure the domains are correct in the development Docker compose file and run:

```sh
docker compose -f docker-compose.dev.yml up --build
```

> [!NOTE]
> I recommend copying the example `docker-compose.dev.yml` into a `docker-compose.test.yml` file, so as you don't accidentally commit any sensitive information.
