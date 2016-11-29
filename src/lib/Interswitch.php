<?php

/**
 * Description of InterswitchAuth
 *
 * @author Abiola.Adebanjo
 */

namespace Interswitch;

//set_include_path('/var/www/html/interswitch/lib');

include_once __DIR__.'/lib/Utils.php';
include_once __DIR__.'/lib/Constants.php';
include_once __DIR__.'/lib/HttpClient.php';
//include_once __DIR__.'/lib/Crypt/RSA.php';
//include_once __DIR__.'/lib/Math/BigInteger.php';
//use \Crypt_RSA;
//use \Math_BigInteger;

class Interswitch {

  private $clientId;
  private $clientSecret;
  private $environment;
  private $accessToken;
  private $signature;
  private $signatureMethod;
  private $nonce;
  private $timestamp;
  const ENV_PRODUCTION = "PRODUCTION";
  const ENV_SANDBOX = "SANDBOX";

public function __construct($clientId, $clientSecret, $environment = null) {
  $this->clientId = $clientId;
  $this->clientSecret = $clientSecret;
  if ($environment !== null) {
    $this->environment = $environment;
  }
}



function send($uri, $httpMethod, $data = null, $headers = null, $signedParameters = null) 
{

  $this->nonce = Utils::generateNonce();
  $this->timestamp = Utils::generateTimestamp();
  $this->signatureMethod = Constants::SIGNATURE_METHOD_VALUE;

  if ($this->environment === NULL) {
    $passportUrl = Constants::SANDBOX_BASE_URL . Constants::PASSPORT_RESOURCE_URL;
    $uri = Constants::SANDBOX_BASE_URL . $uri;
  } else {
    if(strcmp($this->environment, self::ENV_PRODUCTION))
    {
      $passportUrl = Constants::PRODUCTION_BASE_URL . Constants::PASSPORT_RESOURCE_URL;
      $uri = Constants::PRODUCTION_BASE_URL . $uri;
    }
    else
    {
      $passportUrl = Constants::SANDBOX_BASE_URL . Constants::PASSPORT_RESOURCE_URL;
      $uri = Constants::SANDBOX_BASE_URL . $uri;
    }
  }
   
  $this->signature = Utils::generateSignature($this->clientId, $this->clientSecret, $uri, $httpMethod, $this->timestamp, $this->nonce, $signedParameters);

  $passportResponse = Utils::generateAccessToken($this->clientId, $this->clientSecret, $passportUrl);
  if($passportResponse[Constants::HTTP_CODE] === 200) {
    $this->accessToken = json_decode($passportResponse[Constants::RESPONSE_BODY], true)['access_token'];
  } else {
    return $passportResponse;
  }

  $authorization = 'Bearer ' . $this->accessToken;
  
  $constantHeaders = [
    'Authorization: ' . $authorization,
    'SignatureMethod: ' . $this->signatureMethod,
    'Signature: ' . $this->signature,
    'Timestamp: ' . $this->timestamp,
    'Nonce: ' . $this->nonce
  ];

  $contentType = [
    'Content-Type: '. Constants::CONTENT_TYPE
  ];

  if($httpMethod != 'GET')
  {
    $constantHeaders = array_merge($contentType, $constantHeaders);
  }

  if($headers !== null && is_array($headers)) {
    $requestHeaders = array_merge($headers, $constantHeaders);
    $response = HttpClient::send($requestHeaders, $httpMethod, $uri, $data);
  } else {
    $response = HttpClient::send($constantHeaders, $httpMethod, $uri, $data);
  }

  return $response;
}




function sendWithAccessToken($uri, $httpMethod, $accessToken, $data = null, $headers = null, $signedParameters = null) {

  $this->nonce = Utils::generateNonce();
  $this->timestamp = Utils::generateTimestamp();
  $this->signatureMethod = Constants::SIGNATURE_METHOD_VALUE;

  if ($this->environment === NULL) {
    $uri = Constants::SANDBOX_BASE_URL . $uri;
  } else {
    if(strcmp($this->environment, self::ENV_PRODUCTION))
    {
      $uri = Constants::PRODUCTION_BASE_URL . $uri;
    }
    else
    {
      $uri = Constants::SANDBOX_BASE_URL . $uri;
    }
  }
  
  $this->signature = Utils::generateSignature($this->clientId, $this->clientSecret, $uri, $httpMethod, $this->timestamp, $this->nonce, $signedParameters);

  $authorization = 'Bearer ' . $accessToken;

  $constantHeaders = [
    'Authorization: ' . $authorization,
    'SignatureMethod: ' . $this->signatureMethod,
    'Signature: ' . $this->signature,
    'Timestamp: ' . $this->timestamp,
    'Nonce: ' . $this->nonce
  ];

  $contentType = [
    'Content-Type: '. Constants::CONTENT_TYPE
  ];

  if($httpMethod != 'GET')
  {
    $constantHeaders = array_merge($contentType, $constantHeaders);
  }

  //echo "<br>Headers 2: ";
  //print_r($headers);
  if($headers !== null && is_array($headers)) {
   //echo "<br> Headers is not null: " . $headers;
   $requestHeaders = array_merge($headers, $constantHeaders);
   //echo "<br> New merged Headers: " ;
   //print_r($requestHeaders);
   $response = HttpClient::send($requestHeaders, $httpMethod, $uri, $data);
  }
  else {
   //echo "<br>Headers is null";  
   $response = HttpClient::send($constantHeaders, $httpMethod, $uri, $data);
  }

  return $response;
}




function getAuthData($pan, $expDate, $cvv, $pin, $publicModulus = null, $publicExponent = null) {

  /*
  if(is_null($publicModulus))
  {
    $publicModulus = Constants::PUBLICKEY_MODULUS;
  }

  if(is_null($publicExponent))
  {
    $publicExponent = Constants::PUBLICKEY_EXPONENT;
  }

  //echo 'Expo: ' . $publicExponent;
  //echo 'Mod: ' . $publicModulus;

  $authDataCipher = '1Z' . $pan . 'Z' . $pin . 'Z' . $expDate . 'Z' . $cvv;
  $rsa = new Crypt_RSA();
  $modulus = new Math_BigInteger($publicModulus, 16);
  $exponent = new Math_BigInteger($publicExponent, 16);
  $rsa->loadKey(array('n' => $modulus, 'e' => $exponent));
  $rsa->setPublicKey();
  $pub_key = $rsa->getPublicKey();

  //echo 'Mod: ' . $modulus . '<br>';
  //echo 'Exp: ' . $exponent . '<br>';
  //echo 'RSA: ' . $rsa . '<br>';
  //echo 'Pub Key: ' . $pub_key . '<br>';

  openssl_public_encrypt($authDataCipher, $encryptedData, $pub_key);
  $authData = base64_encode($encryptedData);
   */
 
  $authData = Utils::getAuthData($pan, $expDate, $cvv, $pin, $publicModulus, $publicExponent);

  return $authData;
}



function getSecureData($pan, $expDate, $cvv, $pin, $amt, $msisdn, $ttid) 
{
  //echo "<br>Pin: " . $pin;
  //echo "<br>CVV: " . $cvv;
  //echo "<br>Exp Date: " . $expDate;
 
  $options = array(
    'expiry' => $expDate,
    'pan' => $pan,
    'ttId' => $ttid,
    'amount' => $amt,
    'mobile' => $msisdn   
  );

  $pinData = array(
    'pin' => $pin,
    'cvv' => $cvv,
    'expiry' => $expDate
  );

 $secure = Utils::generateSecureData($options, $pinData);

 //echo "<br>Secure Data: " . $secure['secureData'];
 //echo "<br>Pin Block: " . $secure['pinBlock'];
 //echo "<br>Mac: " . $secure['mac'];
 
 return $secure;
}




function getAccessToken() {
    return $this->accessToken;
}

    function getSignature() {
        return $this->signature;
    }

    function getSignatureMethod() {
        return $this->signatureMethod;
    }

    function getNonce() {
        return $this->nonce;
    }

    function getTimestamp() {
        return $this->timestamp;
    }

}

