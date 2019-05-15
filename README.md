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

You may also configure the following options for your site, add a YAML (.yml) file in your application's _config directory :
```
---
Name: my-facebook-member
After:
    - '#facebook-member'
---
SilverStripe\Security\MemberAuthenticator\FacebookHandler:
  graphApiVersion: 'v3.3'
  useFacebookJS: true
  loadFacebookJS: true
```
Options:
- *graphApiVersion* : set the version of the graph API, default is v3.3
- *useFacebookJS* : set to true to use Facebook login popup
- *loadFacebookJS*: set to true if you don't have Facebook Javascript SDK loaded by your applicatio, and you need the module to load it

And that's it.
