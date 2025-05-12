<div align="center">
    <img alt="Tinyauth" title="Tinyauth" width="96" src="docs/logo-rounded.png">
    <h1>Tinyauth</h1>
    <p>The easiest way to secure your apps with a login screen.</p>
</div>

<div align="center">
    <img alt="License" src="https://img.shields.io/github/license/steveiliop56/tinyauth">
    <img alt="Release" src="https://img.shields.io/github/v/release/steveiliop56/tinyauth">
    <img alt="Commit activity" src="https://img.shields.io/github/commit-activity/w/steveiliop56/tinyauth">
    <img alt="Issues" src="https://img.shields.io/github/issues/steveiliop56/tinyauth">
    <img alt="Tinyauth CI" src="https://github.com/steveiliop56/tinyauth/actions/workflows/ci.yml/badge.svg">
    <a title="Crowdin" target="_blank" href="https://crowdin.com/project/tinyauth"><img src="https://badges.crowdin.net/tinyauth/localized.svg"></a>
</div>

<br />

Tinyauth is a simple authentication middleware that adds simple username/password login or OAuth with Google, Github and any generic provider to all of your docker apps. It is designed for traefik but it can be extended to work with other reverse proxies like caddy and nginx.

![Screenshot](docs/screenshot.png)

> [!WARNING]
> Tinyauth is in active development and configuration may change often. Please make sure to carefully read the release notes before updating.

> [!NOTE]
> Tinyauth is intended for homelab use only and it is not made for production use cases. If you are looking for something production ready please use [authentik](https://goauthentik.io) instead.

## Discord

I just made a Discord server for tinyauth! It is not only for tinyauth but general self-hosting and homelabbing. [See you there!](https://discord.gg/eHzVaCzRRd).

## Getting Started

You can easily get started with tinyauth by following the guide in the [documentation](https://tinyauth.app/docs/getting-started.html). There is also an available [docker compose file](./docker-compose.example.yml) that has traefik, whoami and tinyauth to demonstrate its capabilities.

## Documentation

You can find documentation and guides on all of the available configuration of tinyauth in the [website](https://tinyauth.app).

## Contributing

All contributions to the codebase are welcome! If you have any recommendations on how to improve security or find a security issue in tinyauth please open an issue or pull request so it can be fixed as soon as possible!

## Localization

If you would like to help translating the project in more languages you can do so by visiting the [Crowdin](https://crowdin.com/project/tinyauth) page.

## License

Tinyauth is licensed under the GNU General Public License v3.0. TL;DR — You may copy, distribute and modify the software as long as you track changes/dates in source files. Any modifications to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build & install instructions. For more information about the license check the [license](./LICENSE) file.

## Sponsors

Thanks a lot to the following people for providing me with more coffee:

<!-- sponsors --><a href="https://github.com/erwinkramer"><img src="https:&#x2F;&#x2F;github.com&#x2F;erwinkramer.png" width="64px" alt="User avatar: erwinkramer" /></a>&nbsp;&nbsp;<a href="https://github.com/nicotsx"><img src="https:&#x2F;&#x2F;github.com&#x2F;nicotsx.png" width="64px" alt="User avatar: nicotsx" /></a>&nbsp;&nbsp;<a href="https://github.com/SimpleHomelab"><img src="https:&#x2F;&#x2F;github.com&#x2F;SimpleHomelab.png" width="64px" alt="User avatar: SimpleHomelab" /></a>&nbsp;&nbsp;<a href="https://github.com/jmadden91"><img src="https:&#x2F;&#x2F;github.com&#x2F;jmadden91.png" width="64px" alt="User avatar: jmadden91" /></a>&nbsp;&nbsp;<a href="https://github.com/tribor"><img src="https:&#x2F;&#x2F;github.com&#x2F;tribor.png" width="64px" alt="User avatar: tribor" /></a>&nbsp;&nbsp;<a href="https://github.com/eliasbenb"><img src="https:&#x2F;&#x2F;github.com&#x2F;eliasbenb.png" width="64px" alt="User avatar: eliasbenb" /></a>&nbsp;&nbsp;<!-- sponsors -->

## Acknowledgements

Credits for the logo of this app go to:

- **Freepik** for providing the police hat and badge.
- **Renee French** for the original gopher logo.
- **Coderabbit AI** for providing free AI code reviews.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=steveiliop56/tinyauth&type=Date)](https://www.star-history.com/#steveiliop56/tinyauth&Date)
