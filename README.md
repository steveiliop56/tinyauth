<div align="center">
    <img alt="Tinyauth" title="Tinyauth" width="256" src="site/public/logo.png">
    <h1>Tinyauth</h1>
    <p>The easiest way to secure your apps with a login screen.</p>
</div>

<div align="center">
    <img alt="License" src="https://img.shields.io/github/license/steveiliop56/tinyauth">
    <img alt="Release" src="https://img.shields.io/github/v/release/steveiliop56/tinyauth">
    <img alt="Commit activity" src="https://img.shields.io/github/commit-activity/w/steveiliop56/tinyauth">
    <img alt="Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/steveiliop56/tinyauth/release.yml">
    <img alt="Issues" src="https://img.shields.io/github/issues/steveiliop56/tinyauth">
</div>

<br />

Tinyauth is a simple authentication middleware that adds simple username/password login or OAuth with Google, Github and any generic OAuth provider to all of your docker apps. It is made for traefik but it can be extended to work with all reverse proxies like caddy and nginx.

> [!WARNING]
> Tinyauth is in active development and configuration may change often. Please make sure to carefully read the release notes before updating.

> [!NOTE]
> Tinyauth is intended for homelab use and it is not made for production use cases. If you are looking for something production ready please use [authentik](https://goauthentik.io).

## Getting Started

You can easily get started with tinyauth by following the guide on the documentation [here](https://tinyauth.doesmycode.work/docs/getting-started.html). There is also an available docker compose file [here](./docker-compose.example.yml) that has traefik, nginx and tinyauth to demonstrate its capabilities.

## Documentation

You can find documentation and guides on all available configuration of tinyauth [here](https://tinyauth.doesmycode.work).

## Contributing

All contributions to the codebase are welcome! If you have any recommendations on how to improve security or find a security issue in tinyauth please open an issue or pull request so it can be fixed as soon as possible!

## License

Tinyauth is licensed under the GNU General Public License v3.0. TL;DR — You may copy, distribute and modify the software as long as you track changes/dates in source files. Any modifications to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build & install instructions. For more information about the license check the [license](./LICENSE) file.

## Acknowledgements

Credits for the logo of this app go to:

- **Freepik** for providing the police hat and logo.
- **Renee French** for the original gopher logo.
