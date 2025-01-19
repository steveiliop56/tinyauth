# Tinyauth - The easiest way to secure your traefik apps with a login screen

Tinyauth is an extremely simple traefik forward auth proxy that adds a login screen to all of your apps that are using the traefik reverse proxy. Tinyauth is configurable through environment variables and it is only 20MB in size.

## Screenshots

Talk is cheap, here are some screenshots:

|                                         |                                           |
| --------------------------------------- | ----------------------------------------- |
| ![Login](./screenshots/login.png)       | ![Logout](./screenshots/logout.png)       |
| ![Continue](./screenshots/continue.png) | ![Not Found](./screenshots/not-found.png) |

## Getting started

Tinyauth is extremely easy to run since it's shipped as a docker container. I chose to bundle it with busybox so as you can easily debug the API (e.g. using curl) and have some simple linux tools. If you want to get started with an example just check the example docker compose file [here](./docker-compose.example.yml)

## Environment variables

Tinyauth accepts the following environment variables:

| Name       | Description                                             | Default | Required |
| ---------- | ------------------------------------------------------- | ------- | -------- |
| `PORT`     | The port the API listens on.                            | 3000    | no       |
| `ADDRESS`  | The address the API binds on.                           | 0.0.0.0 | no       |
| `SECRET`   | A 32 character long string used for the sessions.       | -       | yes      |
| `ROOT_URL` | The base URL of your domain. (e.g. https://example.com) | -       | yes      |
| `APP_URL`  | The Tinyauth URL. (e.g. https://tinyauth.example.com)   | -       | yes      |
| `USERS`    | Comma seperated list of `user:bcrypt-password-hash`.    | -       | yes      |

## FAQ

### Why?

Why make this project? Well we all know that more powerful alternatives like authentik and authelia exist but when I tried to use them I felt overwhelmed with all the configration options and environment variables I had to configure in order for them to work, so, I decided to make a small alternative in Go to both test my skills and cover my simple login screen needs.

### Is this secure?

Probably, the sessions are managed with the gin sessions package so it should be very secure. It is definitely not made for production but it could easily serve as a simple login screen to all of your homelab apps.

### Do I need to login every time?

No, when you login tinyauth sets a `tinyauth` cookie in your browser that applies to all of the subdomains of the root URL you set.

## License

Tinyauth is licensed under the GNU General Public License v3.0. TL;DR — You may copy, distribute and modify the software as long as you track changes/dates in source files. Any modifications to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build & install instructions.

## Contributing

Any contributions to the codebase are welcome! I am not a cybersecurity person so my code may have some vulnerability, if you find something that could be used to exploit and bypass tinyauth please tell me as soon as possible so I can fix it.

## Acknowledgements

Credits for the logo go to:

- Freepik for providing the hat and police badge.
- Renee French for making the gopher logo.
