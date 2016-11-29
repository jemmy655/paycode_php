<?php

namespace Interswitch;

/**
 * Description of Utils
 *
 * @author Abiola.Adebanjo
 * @author Lekan.Omotayo 
 */
include_once 'Constants.php';
include_once __DIR__.'/Crypt/RSA.php';
include_once __DIR__.'/Math/BigInteger.php';
include_once __DIR__.'/Crypt/TripleDES.php';
include_once __DIR__.'/Crypt/Hash.php';
include_once __DIR__.'/Crypt/DES.php';

use \Crypt_RSA;
use \Math_BigInteger;
use \Crypt_TripleDES;
use \Crypt_Hash;
use \Crypt_DES;

class Utils {

    static function generateNonce() {
        return sprintf('%04X%04X%04X%04X%04X%04X%04X%04X', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535));
    }

    static function generateTimestamp() {
        $date = new \DateTime(null, new \DateTimeZone(Constants::LAGOS_TIME_ZONE));
        return $date->getTimestamp();
    }

    static function generateSignature($clientId, $clientSecretKey, $resourceUrl, $httpMethod, $timestamp, $nonce, $transactionParams) {

        $resourceUrl = strtolower($resourceUrl);
        $resourceUrl = str_replace('http://', 'https://', $resourceUrl);
        $encodedUrl = urlencode($resourceUrl);

        $signatureCipher = $httpMethod . '&' . $encodedUrl . '&' . $timestamp . '&' . $nonce . '&' . $clientId . '&' . $clientSecretKey;

        if (!empty($transactionParams) && is_array($transactionParams)) {
            $parameters = implode("&", $transactionParams);
            $signatureCipher = $signatureCipher . $parameters;
        }

        $signature = base64_encode(sha1($signatureCipher, true));
        return $signature;
    }

    static function generateAccessToken($clientId, $clientSecret, $passortUrl) {
        $content_type = 'application/x-www-form-urlencoded';
        $basicCipher = base64_encode($clientId . ':' . $clientSecret);
        $authorization = 'Basic ' . $basicCipher;

        $headers = [
            'Content-Type: ' . $content_type,
            'Authorization: ' . $authorization
        ];

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $passortUrl);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, "grant_type=client_credentials&scope=profile");
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);

        $curl_response = curl_exec($curl);
        $info = curl_getinfo($curl);
        if ($curl_response === false) {

            curl_close($curl);
            die('error occured during curl exec. Additioanl info: ' . var_export($info));
        }

//        $json = json_decode($curl_response, true);
        $response[Constants::HTTP_CODE] = $info['http_code'];
        $response[Constants::RESPONSE_BODY] = $curl_response;

        curl_close($curl);

        return $response;
    }


static function getAuthData($pan, $expDate, $cvv, $pin, $publicModulus = null, $publicExponent = null) {

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



static function generateSecureData($options, $pinData)
{
    $pinBlock = '0000';
    $expiry = '0000';
    $ttId = mt_rand(0, 900) + 100;
    $pan = "0000000000000000";
    $amt = "";
    $publicKeyModulus = Constants::PUBLICKEY_MODULUS;
    $publicKeyExponent = Constants::PUBLICKEY_EXPONENT;

    if(!empty($options['expiry']))
    {
      $expiry = $options['expiry'];
    }
    if(!empty($options['pan']))
    {
      $pan = $options['pan'];
    }
    if(!empty($options['ttId']))
    {
      $ttId = $options['ttId'];
    }
    if(!empty($options['amount']))
    {
      $amt = $options['amount'];
    }

    //echo "<br>Pin: " . $pinData['pin'];
    //echo "<br>CVV: " . $pinData['cvv'];
    //echo "<br>Exp Date: " . $expiry;
    
    $pinKey = self::generateKey();
    
    if(!empty($options['publicKeyModulus']))
    {
      $publicKeyModulus = $options['publicKeyModulus'];
    }
    if(!empty($options['publicKeyExponent']))
    {
      $publicKeyExponent = $options['publicKeyExponent'];
    }

    $transfer = array(
      'toAccountNumber' => "",
      'toBankCode' => ""
    );

    $rechargeInfo = array(
      'tPhoneNumber' => "",
      'productCode' => ""
    );
    
    $billInfo = array(
      'phoneNumber' => "",
      'customerNumber' => "",
      'billCode' => ""
    );  
      
    $atmTranferInfo = array(
      'customerId' => "",
      'transferCode' => "",
      'institutionCode' => ""
    );

    $additionalInfo = array(
      'transferInfo' => $transfer,
      'rechargeInfo' => $rechargeInfo,
      'billInfo' => $billInfo,
      'atmTransferInfo' => $atmTranferInfo
    );

    $secureOptions = array(
          'pinKey' => $pinKey,
          'macKey' => $pinKey,
          'tid' => $options['mobile'],
          'ttid' => $ttId,
          'amount' => $amt,
          'pan' => $pan,
          'accountNumber' => "",
          'expiryDate' => $expiry,
          'cardName' => "default",
          'publicKeyModulus' => $publicKeyModulus,
          'publicKeyExponent' => $publicKeyExponent,
          'additionalInfo' => $additionalInfo
      );

      $secureData = self::getSecure($secureOptions, 'createcard');
      $macData = self::getMacData('app', $secureOptions);
      $pinBlock = self::getPinBlock($pinData['pin'], $pinData['cvv'], $pinData['expiry'], $pinKey, $ttId);
      $mac = self::getMac($macData, $pinKey);

      //echo "<br>Secure: " . $secureData;
      //echo "<br>Pin Block: " . $pinBlock;
      //echo "<br>Mac Data: ". $macData;
      //echo "<br>Mac: " . $mac;

      $data = [
        'secureData' => $secureData,
        'pinBlock' => $pinBlock,
        'mac' => $mac 
      ];

      
      return $data;
}


   static function getPinBlock($pin, $cvv2, $expiryDate, $pinKey, $randNum)
   {
      if(empty($pin)) {
        $pin = "0000";
      }
      if(empty($cvv2)) {
        $cvv2 = "000";
      }
      if(empty($expiryDate)) {
        $expiryDate = "0000";
      }

      //echo "<br>Pin: " . $pin;
      //echo "<br>CVV: " . $cvv2;
      //echo "<br>Exp Date: " . $expiryDate;

      $pinBlockString = $pin . $cvv2 . $expiryDate;
      $pinBlockStringLen = strlen($pinBlockString);
      $pinBlockStringLenLen = strlen($pinBlockStringLen);
      $clearPinBlock = $pinBlockStringLenLen . $pinBlockStringLen . $pinBlockString;
      //echo "<br>Clear Pin Block: " . $clearPinBlock;
   
      $randomNumber = substr($randNum, 0, 1);
      //echo "<br>Rand: " . $randomNumber;

      $pinPadLen = 16 - strlen($clearPinBlock);
      //echo "<br>Remaing Len: " . $pinPadLen;

      for ($i = 0; $i < $pinPadLen; $i++) {
        $clearPinBlock = $clearPinBlock . $randomNumber;
      }
  
      //echo "<br>Clear Pin Block: " . $clearPinBlock;
      //echo "<br>Key: " . self::print_array($pinKey);

      $des = new Crypt_TripleDES();
      //$iv = "\0\0\0\0\0\0\0\0";
      //$des->setIV($iv);

      $pinKeyHex =  strtoupper(bin2hex($pinKey));
      //echo "<br>Key Hex: " . $pinKeyHex;

      $des->setKey($pinKey);
      $des->disablePadding();
      $cipherTextBin = hex2bin($clearPinBlock);
      //echo "<br>Cipher Text Bin: " . $cipherTextBin;
      $encryptedPinBlock = $des->encrypt($cipherTextBin);
      //echo "<br>Encrypted PinBlock Bytes: " . self::print_array($encryptedPinBlock);
      $pinBlockHex = bin2hex($encryptedPinBlock);
      //echo "<br>Encrypted PinBlock Hex: " . $pinBlockHex;

      return $pinBlockHex;
   }


   static function getMacData($app, $options) 
   {
    
    $macData = "";
    if (empty($app)) {
        return $macData;
    }
    if (!empty($options['tid'])) {
        $macData = $macData . $options['tid'];
    }

    if (!empty($options['cardName'])) {
        $macData = $macData . $options['cardName'];
    }
    if (!empty($options['ttid'])) {
        $macData = $macData . $options['ttid'];
    }

    if (!empty($options['amount'])) {
        $macData = $macData . $options['amount'];
    }

    if (empty($options['additionalInfo'])) {
        return $macData;
    }

    $additionalInfo = $options['additionalInfo'];

    if (!empty($additionalInfo['transferInfo'])) {
        $transferInfo = $additionalInfo['transferInfo'];
        if (!empty($transferInfo['toAccountNumber'])) {
            $macData = $macData . $transferInfo['toAccountNumber'];
        }

        if (!empty($transferInfo['toBankCode'])) {
            $macData = $macData . $transferInfo['toBankCode'];
        }
    }

    if (!empty($additionalInfo['billInfo'])) {
        $billInfo = $additionalInfo['billInfo'];
        if (!empty($billInfo['phoneNumber'])) {
            $macData = $macData . $billInfo['phoneNumber'];
        }
        if (!empty($billInfo['customerNumber'])) {
            $macData = $macData . $billInfo['customerNumber'];
        }

        if (!empty($billInfo['billCode'])) {
            $macData = $macData . $billInfo['billCode'];
        }

    }

   if (!empty($additionalInfo['rechargeInfo'])) {
        $rechargeinfo = $additionalInfo['rechargeInfo'];
        if (!empty($rechargeInfo['tPhoneNumber'])) {
            $macData = $macData . $rechargeInfo['tPhoneNumber'];
        }
        if (!empty($rechargeInfo['productCode'])) {
            $macData = $macData . $rechargeInfo['productCode'];
        }

    }

    if (!empty($additionalInfo['atmTransferInfo'])) {
        $atmTransferInfo = $additionalInfo['atmTransferInfo'];
        if (!empty($atmTransferInfo['customerId'])) {
            $macData = $macData . $atmTransferInfo['customerId'];
        }
        if (!empty($atmTransferInfo['institutionCode'])) {
            $macData = $macData . $atmTransferInfo['institutionCode'];
        }

    }
    return $macData;
}



   static function getMac($macData, $macKey)
   {
    //do hmac here
    $hash = new Crypt_Hash('sha256');
    $hash->setKey($macKey);
    $mac = $hash->hash($macData);
    $macHex = bin2hex($mac);
    return $macHex;
   }



   static function getSecure($options, $app, $isActivate = false) 
   {

    //TODO Temporary Activate eCash
    $versionHex = "12";

    if($isActivate)
    {
      $versionHex = "10";
    }

    // echo  "<br> Options: " . print_r($options);
    $headerHex = "4D";
    $headerBytes = pack("H*", $headerHex);
    //echo "<br>Headerbytes-lenght : " . strlen($headerBytes);
    //echo "<br>Headerbytes : " . self::print_array($headerBytes);
    //echo '<br>Headers: '. $headerHex;
    
    $formatVersionHex = $versionHex;
    $formatVersionBytes = pack("H*", $formatVersionHex);
    //echo "<br>formatVersionBytes-lenght : " . strlen($formatVersionBytes);
    //echo "<br>formatVersionBytes : " . self::print_array($formatVersionBytes);
    //echo "<br>formatVersionHex : " . $formatVersionHex;

    $macVersionHex = $versionHex;
    $macVersionBytes = pack("H*", $macVersionHex);
    //echo "<br>macVersionBytes-lenght : " . strlen($macVersionBytes);
    //echo "<br>macVersionBytes : " . self::print_array($macVersionBytes);
    //echo "<br>macVersionHex : " . $macVersionHex;

    $pinDesKeyBytes = $options['pinKey'];
    $pinDesKeyHex = bin2hex($pinDesKeyBytes);
    //echo "<br>pinDesKey-lenght : " . strlen($pinDesKeyBytes);
    //echo "<br>pinDesKeyBytes : " . self::print_array($pinDesKeyBytes);
    //echo "<br>pinDesKeyHex : " . $pinDesKeyHex;

    $macDesKeyBytes = $options['macKey'];
    $macDesKeyHex = bin2hex($macDesKeyBytes);
    //echo "<br>macDesKey-lenght : " . strlen($macDesKeyBytes);
    //echo "<br>macDesKeyBytes : " . self::print_array($macDesKeyBytes);
    //echo "<br>macDesKeyHex : " . $macDesKeyHex;

    $customerIdHex;
    if (!empty($options['pan'])) {
        $customerId = $options['pan'];
        $customerIdLen = strlen($customerId);
        $customerIdLenLen = strlen($customerIdLen);
        $customerIdBlock = $customerIdLenLen . $customerIdLen . $customerId;
        $customerIdBlockLen = strlen($customerIdBlock);
 	//echo "<br>Customer Id: " . $customerIdBlock;      

        $maxLen = 20;
        $pandiff = $maxLen - $customerIdBlockLen;
        for ($i = 0; $i < $pandiff; $i++) {
            $customerIdBlock = $customerIdBlock . "F";
        }

        $customerIdHex = self::padRight($customerIdBlock, $maxLen);
        $customerIdBytes = pack("H*", $customerIdHex);
        //echo "<br>customerIdBytes-lenght : " . strlen($customerIdBytes);
        //echo "<br>customerIdBytes 1 : " . self::print_array($customerIdBytes);
        //echo "<br>CustomerIdHex: " . $customerIdHex;
    }

    $macData = self::getMacData($app, $options);
    //echo "<br>MacData : " . $macData;
    $macHex = self::getMac($macData, $macDesKeyBytes);
    //echo "<br>Mac Hex: " . $macHex;
    $macHex = substr($macHex, 0, 8);
    $macBytes = pack("H*", $macHex);
    //echo "<br>macBytes-lenght : " . strlen($macBytes);
    //echo "<br>macBytes : " . self::print_array($macBytes);
    //echo "<br>Mac Hex : " . $macHex;

    $otherHex = "0000000000000000000000000000";
    $otherBytes = pack("H*", $otherHex);
    //echo "<br>otherBytes-lenght : " . strlen($otherBytes);
    //echo "<br>otherBytes : " . self::print_array($otherBytes);
    //echo "<br>otherHex: " . $otherHex;

    $footerHex = "5A";
    $footerBytes = pack("H*", $footerHex);
    //echo "<br>footerBytes-lenght : ". strlen($footerBytes);
    //echo "<br>footerBytes: " . self::print_array($footerBytes);
    //echo "<br>footerHex: " . $footerHex;

    $clearSecureHex = $headerHex .$formatVersionHex .$macVersionHex .$pinDesKeyHex .$macDesKeyHex .$customerIdHex .$macHex .$otherHex .$footerHex;
    $clearSecureBytes = pack("H*", $clearSecureHex);
    //echo "<br>Clear secure-length: " . strlen($clearSecureBytes);
    //echo "<br>Clear secure bytes: " . self::print_array($clearSecureBytes);
    //echo "<br>Clear Secure hex: " . $clearSecureHex;

    $rsa = new Crypt_RSA();
    $modulus = new Math_BigInteger(Constants::PUBLICKEY_MODULUS, 16);
    $exponent = new Math_BigInteger(Constants::PUBLICKEY_EXPONENT, 16);
    $rsa->loadKey(array('n' => $modulus, 'e' => $exponent));
    $pub_key = $rsa->getPublicKey();

    $cipher = new Crypt_RSA();
    $cipher->loadKey($pub_key);
    //Set the encryption mode
    $cipher->setEncryptionMode(CRYPT_RSA_ENCRYPTION_NONE);
    $encryptedData = $cipher->encrypt($clearSecureBytes);

    $secureHex = bin2hex($encryptedData);
    //echo "<br>Secure-hex: " . $secureHex;
    return $secureHex;
}



static function padRight($value, $maxLen) {
    $maxLength = $maxLen;
    $stringValue = $value;
    if (empty($stringValue) || strlen($stringValue) >= $maxLength) {
        return $stringValue;
    }
    $length = strlen($stringValue);
    $deficitLength = $maxLength - $length;
    for ($i = 0; $i < $deficitLength; $i++) {
        $stringValue = $stringValue . "0";
    }
    return $stringValue;
}

static function padLeft($value, $maxLen) {
    $maxLength = $maxLen;
    $stringValue = $value;
    if (empty($stringValue) || strlen($stringValue) >= $maxLength) {
        return $stringValue;
    }
    $length = strlen($stringValue);
    $deficitLength = $maxLength - $length;
    for ($i = 0; $i < $deficitLength; $i++) {
        $stringValue = "0" . $stringValue;
    }
    return $stringValue;
}

    static function generateKey() {
        $crypto_strong = true;
	$bytes = openssl_random_pseudo_bytes(16, $crypto_strong);
        //echo '<br>Key in bytes: ' . self::print_array($bytes);
	//echo '<br>Key in hex: ' . bin2hex($bytes);
        return $bytes;
    }

static function print_array($var)
{
  echo "<br>";
  for($i = 0; $i < strlen($var); $i++)
  {
    echo "[" . ord($var[$i]) . "], ";
  }
}


static function asc2bin($asc) 
{
  $result = '';
  $len = strlen($asc);
  for ($i = 0; $i < $len; $i++)
  {
    if( ord ($asc[$i])  < 255)
    {
      //$result .=sprintf("%08b",ord($asc[$i]));
      $result .= ord($asc[$i]);  
    }
    else
    {
      $result .=sprintf("%08b",-1);
    }
  }
  return $result;
}


/*
static function bin2ascii($bin)
{
$result = '';
$len = strlen($bin);
for ($i = 0; $i < $len; $i += 8)
{
$result .= chr(bindec(substr($bin,$i,8)));
}
return $result; 
}
*/

static function hexDecode($data)
{
  $out = "";
  $end = strlen($data);
  while($end > 0)
  {
    if(!self::ignore($data[$end - 1]))
    {
      break;
    }
    $end--;
  }

  $i =0;
  while($i < $end)
  {
    while($i < $end && self::ignore($data[$i]))
    {
      $i++;
    } 

    $b1 = self::decodingTable($data[$i++]);
    while($i < $end && self::ignore($data[$i]))
    {
      $i++;
    }
    $b2 = self::decodingTable($data[$i++]);

    echo "<br>Bytes: " .$b1 . $b2 . "";
    $tmp = (($b1 << 4) | $b2);
    if($tmp > 254)
     $tmp = -1;
    echo "<br>Bytes: " .$b1 . $b2 . " Hex: " . $tmp;
    //echo "<br> Hex Byte: ". $tmp;
    $out .= $tmp;
  }

  return $out;
}

static function decodingTable($b)
{
  if($b == 'a')
    return '10';
  if($b == 'b')
    return '11';
  if($b == 'c')
    return '12';
  if($b == 'd')
    return '13';
  if($b == 'e')
    return '14';
  if($b == 'f')
    return '15';
  if($b == 'A')
    return '10';
  if($b == 'B')
    return '11';
  if($b == 'C')
    return '12';
  if($b == 'D')
    return '13';
  if($b == 'E')
    return '14';
  if($b == 'F')
    return '15';

   return $b;  
}

static function ignore($c)
{
  return ctype_space($c);
}
}

