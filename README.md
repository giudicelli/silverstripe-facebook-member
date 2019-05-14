silverstripe-facebook-member
=======

Allows users to log into Silverstripe using their Facebook account

## Installation

```sh
composer require giudicelli/silverstripe-facebook-member
```

## Configuration

Edit your .env file and add the following entries:
- FACEBOOK_APP_ID with your application's id
- FACEBOOK_APP_SECRET with your application's secret

Next you will need to configure your application on Facebook to make sure
the OAuth callback is allowed, it will be located in https:/yoursite//Security/login/facebookauthenticator/confirm

And that's it.
