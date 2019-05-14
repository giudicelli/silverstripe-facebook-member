<?php

namespace SilverStripe\Security\MemberAuthenticator;

use InvalidArgumentException;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Extensible;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\DefaultAdminService;
use SilverStripe\Security\LoginAttempt;
use SilverStripe\Security\Member;
use SilverStripe\Security\PasswordEncryptor;
use SilverStripe\Security\Security;

/**
 * Authenticator for the default "member" method
 *
 * @author Sam Minnee <sam@silverstripe.com>
 * @author Simon Erkelens <simonerkelens@silverstripe.com>
 */
class FacebookAuthenticator extends MemberAuthenticator
{
    use Extensible;

    public function supportedServices()
    {
        // Bitwise-OR of all the supported services in this Authenticator, to make a bitmask
        return Authenticator::LOGIN;
    }

    /**
     * @param string $link
     * @return FacebookHandler
     */
    public function getLoginHandler($link)
    {
        return FacebookHandler::create($link, $this);
    }
}
