<?php
/**
 * Description of Paycode
 *
 * @author Lekan.Omotayo
 */

require_once __DIR__.'/lib/Interswitch.php';

if(!class_exists("JWT"))
{
  require_once __DIR__.'/lib/lib/JWT.php';
}

use Interswitch\Interswitch as Interswitch;
use \JWT as JWT;

class Paycode {

private $clientId;
private $clientSecret;
private $environment;
private $interswitch;

const HTTP_CODE = "HTTP_CODE";
const RESPONSE_BODY = "RESPONSE_BODY";


public function __construct($clientId, $clientSecret, $environment = null) {
  $this->clientId = $clientId;
  $this->clientSecret = $clientSecret;
  if ($environment !== null) {
    $this->environment = $environment;
  }
  $this->interswitch = new Interswitch($this->clientId, $this->clientSecret, $this->environment);
}


function getEWallet($accessToken)
{
  return $this->interswitch->sendWithAccessToken("api/v1/ewallet/instruments", "GET", $accessToken);
}

function generateWithEWallet($accessToken, $paymentMethodIdentifier, $expDate, $cvv, $pin, $amt, $fep, $tranType, $pwmChannel, $tokenLifeInMin, $otp)
{

  //echo "<br>Pin: " . $pin;
  //echo "<br>CVV: " . $cvv;
  //echo "<br>Exp Date: " . $expDate;

  $ttid = Paycode::Randomize();
  $decoded = JWT::decode($accessToken, null, false);
  $msisdn = $decoded->mobileNo;
  $secure = $this->interswitch->getSecureData(null, $expDate, $cvv, $pin, null, $msisdn, $ttid);

  $secureData = $secure['secureData'];
  $pinData = $secure['pinBlock'];
  $macData = $secure['mac'];

  //echo "<br>Secure Data: " . $secure['secureData'];
  //echo "<br>Pin Block: " . $secure['pinBlock'];
  //echo "<br>Mac: " . $secure['mac'];

  $httpHeader = [
     'frontendpartnerid: '. $fep
  ];

  //echo '<br>Mobile No: ' . $msisdn;

  $req = array(
    "amount" => $amt,
    "ttid" => $ttid,
    "transactionType" => $tranType,
    "paymentMethodIdentifier" => $paymentMethodIdentifier,
    "payWithMobileChannel" => $pwmChannel,
    "tokenLifeTimeInMinutes" => $tokenLifeInMin,
    "oneTimePin" => $otp,
    "pinData" => $pinData,
    "secure" => $secureData,
    "macData" => $macData
   );
   $jsonReq = json_encode($req);

  //echo "<br>Generate Paycode Req: " . $jsonReq;
  //echo "<br>Headers 1: ";
  //print_r($httpHeader);
  return $this->interswitch->sendWithAccessToken("api/v1/pwm/subscribers/" . $msisdn . "/tokens", "POST", $accessToken, $jsonReq, $httpHeader);
}

static function Randomize() {
    return mt_rand(0, 999);
}

}

