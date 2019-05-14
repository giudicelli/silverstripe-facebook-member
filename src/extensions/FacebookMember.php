<?php

namespace SilverStripe\Security\MemberAuthenticator;

use SilverStripe\ORM\DataExtension;

class FacebookMember extends DataExtension 
{
    private static $db = [
        'FacebookId' => 'BigInt',
        'FacebookToken' => 'Text',
        'FacebookTokenExpires' => 'DBDatetime'
    ];

    private static $indexes = [
        'FacebookId' => true
    ];
    
    /**
     * Veto lost password if user is a FB account
     */
    function forgotPassword() {
        if($this->owner->FacebookToken)
            return false;
        return true;
    }

}
