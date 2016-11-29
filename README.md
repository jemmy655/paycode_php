# paycode_php
Interswitch Paycode PHP Library


## Installation

Install the latest version with

```bash
$ composer require Interswitch\Paycode
```

## Basic Usage

```php
<?php

use Interswitch\Paycode;

// Initialize Interswitch object
$CLIENT_ID = "IKIA9614B82064D632E9B6418DF358A6A4AEA84D7218";
$CLIENT_SECRET = "XCTiBtLy1G9chAnyg0z3BcaFK4cVpwDg/GTw2EmjTZ8=";
$paycode = new Paycode($CLIENT_ID, $CLIENT_SECRET);
$accessToken = ''; // Get user access token from Interswitch Passport (https://sandbox.interswitchng.com/passport/oauth/authorize) or https://saturn.interswitchng.com/passport/oauth/authorize.

// Build request data
$cardExpDate = "1909"; // Select Payment Token Expiry Date
$cvv = "123"; // Select Payment Token CVV
$pin = "1234"; // Select Payment Token PIN
$pwmChannel = "ATM"; // Paycode is for use at ATM. Possible options: ATM, POS, AGENT
$tokenLifeInMin = "90"; // Paycode expiry time
$otp = "1234"; // Paycode One Time PIN
$amt = "500000"; // Paycode Amount
$tranType = "Withdrawal"; // Paycode for Cash Withdrawal. Possible options: "Withdrawal", "Payment"
$fep = 'WEMA'; // Assigned by Interswitch

// Get eWallet
$eWalletResp = $paycode->getEWallet($accessToken);
$httpResp = $eWalletResp['HTTP_CODE'];
$respBody = $eWalletResp['RESPONSE_BODY'];
$json_resp = json_decode($respBody);
  
if($httpResp == 200)
{
  // Select one of the many eWallet returned
  $paymentToken = $json_resp->paymentMethods[1]->token;
  
  // Generate a Paycode from the payment token selected
  $paycodeResp = $paycode->generateWithEWallet($accessToken, $paymentToken, $cardExpDate, $cvv, $pin, $amt, $fep, $tranType, $pwmChannel, $tokenLifeInMin, $otp);
  $paycodeHttpResp = $paycodeResp['HTTP_CODE'];
  $paycodeRespBody = $paycodeResp['RESPONSE_BODY'];
  $json_paycode_resp = json_decode($paycodeRespBody);
  if($paycodeHttpResp == 200 || $paycodeHttpResp == 201)
  {
    $paycodeToken = $json_paycode_resp->payWithMobileToken; // Paycode
    $tokenLifeMin = $json_paycode_resp->tokenLifeTimeInMinutes; // Expiry Time
  }
}
```


## Third Party Packages

- interswitch
- JWT

## About

### Requirements

- Intersiwtch SDK works with PHP 5.0 or above.

### Author

Lekan Omotayo - <developer@interswitchgroup.com><br />

### License

Paycode SDK is licensed under the ISC License



