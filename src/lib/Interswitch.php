<?php

/**
 * Description of InterswitchAuth
 *
 * @author Abiola.Adebanjo
 */

namespace Interswitch;


include_once __DIR__.'/lib/Utils.php';
include_once __DIR__.'/lib/Constants.php';
include_once __DIR__.'/lib/HttpClient.php';
include_once __DIR__.'/lib/Crypt/RSA.php';
include_once __DIR__.'/lib/Math/BigInteger.php';

use \Crypt_RSA;
use \Math_BigInteger;

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
   'Content-Type: ' . Constants::CONTENT_TYPE,
   'Authorization: ' . $authorization,
   'SignatureMethod: ' . $this->signatureMethod,
   'Signature: ' . $this->signature,
   'Timestamp: ' . $this->timestamp,
   'Nonce: ' . $this->nonce
  ];

  if($headers !== null && is_array($headers)) {
   $requestHeaders = array_merge($headers, $constantHeaders);
   $response = HttpClient::send($requestHeaders, $httpMethod, $uri, $data);
  } else {
   $response = HttpClient::send($constantHeaders, $httpMethod, $uri, $data);
  }

  return $response;
}




function getAuthData($pan, $expDate, $cvv, $pin, $publicModulus = null, $publicExponent = null) {

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

  return $authData;
}

function getSecureData($publicCertPath, $pan, $expDate, $cvv, $pin) 
{
  $secureData["SECURE"] = Constants::API_JAM_SECURE_DATA;
  $secureData["PINBLOCK"] = Constants::API_JAM_SECURE_DATA;
 
 return $secureData;
}


/*  
  function getAuthData($publicCertPath = null, $version, $pan, $expDate, $cvv, $pin) {
        $authDataCipher = $version . 'Z' . $pan . 'Z' . $pin . 'Z' . $expDate . 'Z' . $cvv;

        if ($publicCertPath == null) {
            $publicCertPath = '..\paymentgateway.crt';
        }

        $fp = fopen($publicCertPath, "r");
        $pub_key = fread($fp, 8192);
        fclose($fp);

        openssl_public_encrypt($authDataCipher, $encryptedData, $pub_key);

        $authData = base64_encode($encryptedData);

        return $authData;
    }
*/



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

