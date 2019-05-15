<?php

namespace SilverStripe\Security\MemberAuthenticator;

use SilverStripe\Core\Environment;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\Email\Email;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\Core\Config\Config;

/**
 * Handle register requests from MemberFacebookForm
 */
class FacebookHandler extends RequestHandler
{
    private static $graphApiVersion = 'v3.3';
    private static $useFacebookJS = false;
    private static $loadFacebookJS = false;

    /**
     * @var Authenticator
     */
    protected $authenticator;

    /**
     * @var array
     */
    private static $url_handlers = [
        '' => 'register',
    ];

    /**
     * @var array
     * @config
     */
    private static $allowed_actions = [
        'register',
        'confirm',
        'FacebookForm'
    ];

    /**
     * Link to this handler
     *
     * @var string
     */
    protected $link = null;

    /**
     * @param string $link The URL to recreate this request handler
     * @param FacebookAuthenticator $authenticator The authenticator to use
     */
    public function __construct($link, FacebookAuthenticator $authenticator)
    {
        $this->link = $link;
        $this->authenticator = $authenticator;
        parent::__construct();
    }

    /**
     * Return a link to this request handler.
     * The link returned is supplied in the constructor
     *
     * @param null|string $action
     * @return string
     */
    public function Link($action = null)
    {
        $link = Controller::join_links($this->link, $action);
        $this->extend('updateLink', $link, $action);
        return $link;
    }

    /**
     * URL handler for the register screen
     *
     * @return array
     */
    public function register()
    {
        return [
            'Form' => $this->FacebookForm(),
        ];
    }

    /**
     * URL handler for the confirmation screen
     *
     * @return array
     */
    public function confirm()
    {        
        $form = $this->FacebookForm();

        $link = Security::singleton()->Link('login');
        $link = Controller::join_links(
            $this->addBackURLParam($link),
            '#' . $form->FormName()
        );
        $request = $this->getRequest();
        $error = $request->getVar('error_description');
        if($error) {
            $form->sessionMessage($error, 'bad');
            return $this->redirect($link);
        }
        
        // Now verify the token
        $fb = new \Facebook\Facebook([
            'app_id' => Environment::getEnv('FACEBOOK_APP_ID'),
            'app_secret' => Environment::getEnv('FACEBOOK_APP_SECRET'),
            'default_graph_version' => Config::inst()->get(static::class, 'graphApiVersion')
        ]);

        $helper = $fb->getRedirectLoginHelper();
        try {
            $accessToken = $helper->getAccessToken();
        }
        catch(\Exception $e) {
            $form->sessionMessage($e->getMessage(), 'bad');
            // Fail to register redirects back to form
            return $this->redirect($link);
        }

        if(!isset($accessToken)) {
            if ($helper->getError()) {
                $form->sessionMessage($helper->getErrorDescription(), 'bad');
            }
            else {
                $form->sessionMessage(_t(__CLASS__.'INVALIDTOKEN', 'Failed to validate token'), 'bad');
            }
            // Fail to register redirects back to form
            return $this->redirect($link);
        }

        $error = '';
        $member = $this->importMember($fb, $accessToken, $error);
        if(!$member) {
            $form->sessionMessage($error, 'bad');
            return $this->redirect($link);
        }

        // Perform login
        $identityStore = Injector::inst()->get(IdentityStore::class);
        $identityStore->logIn($member, false, $request);
        return $this->redirectAfterSuccessfulLogin();
    }

    /**
     * Return the MemberFacebookForm form
     *
     * @skipUpgrade
     * @return MemberFacebookForm
     */
    public function FacebookForm()
    {
        return MemberFacebookForm::create(
            $this,
            get_class($this->authenticator),
            'FacebookForm'
        );
    }

    /**
     * Facebook form handler method
     *
     * This method is called when the user begins the register flow
     *
     * @param array $data Submitted data
     * @param MemberFacebookForm $form
     * @param HTTPRequest $request
     * @return HTTPResponse
     */
    public function doLogin($data, MemberFacebookForm $form, HTTPRequest $request)
    {
        $fb = new \Facebook\Facebook([
            'app_id' => Environment::getEnv('FACEBOOK_APP_ID'),
            'app_secret' => Environment::getEnv('FACEBOOK_APP_SECRET'),
            'default_graph_version' => Config::inst()->get(static::class, 'graphApiVersion')
        ]);

        $useFacebookJS = Config::inst()->get(self::class, 'useFacebookJS');
        if($useFacebookJS) {
            // Using Facebook Javascript SDK
            $helper = $fb->getJavaScriptHelper();
            try {
                $accessToken = $helper->getAccessToken();
            }
            catch(\Exception $e) {
            }

            if(isset($accessToken)) {
                // We have an access token, try to import the user
                $error = '';
                $member = $this->importMember($fb, $accessToken, $error);
                if($member) {
                    // Perform login
                    $identityStore = Injector::inst()->get(IdentityStore::class);
                    $identityStore->logIn($member, false, $request);
                    return $this->redirectAfterSuccessfulLogin();
                }
            }
        }
        
        // Default method, or fallback on a failed Javascript login
        $helper = $fb->getRedirectLoginHelper();
        $permissions = ['email', 'public_profile'];
        $loginUrl = $helper->getLoginUrl(Director::absoluteURL($this->Link('confirm')), $permissions);
        return $this->redirect($loginUrl);
    }
    
    protected function importMember($fb, $accessToken, &$error) {
        // Logged in
        //var_dump($accessToken->getValue());
        // The OAuth 2.0 client handler helps us manage access tokens
        $oAuth2Client = $fb->getOAuth2Client();

        // Get the access token metadata from /debug_token
        $tokenMetadata = $oAuth2Client->debugToken($accessToken);

        try {
            // Validation (these will throw FacebookSDKException's when they fail)
            $tokenMetadata->validateAppId(Environment::getEnv('FACEBOOK_APP_ID'));
            // If you know the user ID this access token belongs to, you can validate it here
            //$tokenMetadata->validateUserId('123');
            $tokenMetadata->validateExpiration();
        }
        catch(\Exception $e) {
            $error = $e->getMessage();
            return false;
        }


        if(!$accessToken->isLongLived()) {
            // Exchanges a short-lived access token for a long-lived one
            try {
                $accessToken = $oAuth2Client->getLongLivedAccessToken($accessToken);
            }
            catch(\Exception $e) {
                $error = $e->getMessage();
                return false;
            }
        }

        try {
            // Get the \Facebook\GraphNodes\GraphUser object for the current user.
            $response = $fb->get('/me?fields=id,first_name,last_name,email', $accessToken);
            $me = $response->getGraphUser();
        }
        catch(\Exception $e) {
            $error = $e->getMessage();
            return false;
        }
        
        //print_r($me); die();
        
        // First search by Facebook ID
        $member = Member::get()
            ->filter(['FacebookId' => $me->getField('id')])
            ->first();

        if(!$member) {
            // The by email
            $member = Member::get()
                ->filter(['Email' => $me->getField('email')])
                ->first();
            if(!$member) {
                // Create the user
                $member = Member::create();
            }
        }
        // Force the information from Facebook
        $member->Email = $me->getField('email');
        $member->FirstName = $me->getField('first_name');
        $member->Surname = $me->getField('last_name');
        $member->FacebookId = $me->getField('id');
        $member->FacebookToken = (string)$accessToken;
        $member->FacebookTokenExpires = date('Y-m-d H:i:s', $tokenMetadata->getField('expires_at')->getTimestamp());
        $member->write();
        
        return $member;
    }
    

    /**
     * Register in the user and figure out where to redirect the browser.
     *
     * The $data has this format
     * array(
     *   'AuthenticationMethod' => 'FacebookAuthenticator',
     *   'Email' => 'sam@silverstripe.com',
     *   'Password' => '1nitialPassword',
     *   'BackURL' => 'test/link',
     *   [Optional: 'Remember' => 1 ]
     * )
     *
     * @return HTTPResponse
     */
    protected function redirectAfterSuccessfulLogin()
    {
        $this
            ->getRequest()
            ->getSession()
            ->clear('SessionForms.MemberFacebookForm.Email')
            ->clear('SessionForms.MemberFacebookForm.Remember');

        $member = Security::getCurrentUser();

        // Absolute redirection URLs may cause spoofing
        $backURL = $this->getBackURL();
        if ($backURL) {
            return $this->redirect($backURL);
        }

        // If a default register dest has been set, redirect to that.
        $defaultRegisterDest = Security::config()->get('default_login_dest');
        if ($defaultRegisterDest) {
            return $this->redirect($defaultRegisterDest);
        }

        // Redirect the user to the page where they came from
        if ($member) {
            // Welcome message
            $message = _t(
                'SilverStripe\\Security\\Member.WELCOMEBACK',
                'Welcome Back, {firstname}',
                ['firstname' => $member->FirstName]
            );
            Security::singleton()->setSessionMessage($message, ValidationResult::TYPE_GOOD);
        }

        // Redirect back
        return $this->redirectBack();
    }
}
