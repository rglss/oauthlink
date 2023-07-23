# OAuthLink - Joomla OAuth2 Plugin for Azure

![OAuthLink Logo](oauthlink-logo.png)

OAuthLink is a Joomla plugin that integrates with Azure Active Directory (Azure AD) and allows seamless user authentication and user profile synchronization using Microsoft Graph API.

## Features

- Single Sign-On (SSO): Users can log in to Joomla using their Azure AD credentials, providing a unified login experience.
- User Profile Synchronization: Keep user profiles up-to-date by synchronizing data with Azure AD through Microsoft Graph.
- Group and Role Mapping: Map Azure AD groups to Joomla user groups for role-based access control.
- User Attribute Mapping: Map properties from Azure AS to Joomla Users via the Microsoft Graph API
- User Provisioning: Enable automatic user provisioning in Joomla based on Azure AD user creation.

## Requirements

- Joomla CMS 3.9 or later
- PHP 7.3 or later
- An Azure Active Directory tenant and an Azure AD application for OAuth authentication.

## Installation

1. Download the latest release from the [Releases](https://github.com/rglss/OAuthLink/releases) page.
2. Install the plugin using the Joomla Administrator panel. Navigate to Extensions → Manage → Install.
3. Configure the plugin settings in Extensions → Plugins → OAuthLink.

## Configuration

TBC

## Usage

TBC

## Credits
OAuthLink is essentially a Joomla wrapper around the fantastic [oauth2-azure](https://github.com/TheNetworg/oauth2-azure) library, big kudos to it's contributors for making this plugin a breeze to write.

Additional credit to the [joomla-onelogin](https://github.com/onelogin/joomla-saml) plugin, from which this takes inspiration.

## Contributing

We welcome contributions and bug reports! Please see our [Contribution Guidelines](CONTRIBUTING.md) for details on how to contribute to OAuthLink.

## License

This project is licensed under the [MIT License](LICENSE).

## Support

For any questions or issues, please open an issue on the [GitHub repository](https://github.com/rglss/OAuthLink/issues).

---

**Disclaimer:** This project is not affiliated with or endorsed by Microsoft or Joomla. Microsoft and Azure are registered trademarks of Microsoft Corporation. Joomla is a registered trademark of Open Source Matters, Inc.
