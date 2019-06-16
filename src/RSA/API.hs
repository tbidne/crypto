{-|
Module      : RSA.API
Description : API for RSA functions.
License     : MIT
Maintainer  : tbidne@gmail.com

This is the API for the main RSA functions. Supports 1024, 2048, and 4096 bit keys.
This is for file encryption, so it encrypts the file with AES-256 then encrypts
the AES key using RSA. For RSA public key @pk@, generated AES key @k@, and message @m@,
the ciphertext is:

@
(Enc_RSA_pk(k)|Enc_AES_k(m))
@
-}
module RSA.API
( keygenIO
, encryptIO
, decryptIO
, keygen
, encrypt
, decrypt
) where

import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (append, empty, pack, readFile, unpack, writeFile)
import           Data.Word ()
import           Data.Either (fromRight)
import           System.Random (RandomGen, newStdGen)

import qualified AES.API as AES
import qualified Common as C
import qualified NumberTheory as NT
import           RSA.Internal (Key (..))
import qualified RSA.Internal as Internal

-- | For 'Integral' @n@, 'String' @pkFileOut@, 'String' @skFileOut@, creates an
-- @n@ bit @(pk, sk)@ key pair and writes the keys to @pkFileOut@ and @skFileOut@,
-- respectively.
keygenIO :: Integral a => a -> String -> String -> IO ()
keygenIO size pubFileOut prvFileOut = do
  g <- newStdGen
  case keygen g size of
    Nothing -> putStrLn "wrong file size"
    Just (pk, sk) -> do
      BS.writeFile pubFileOut pk
      BS.writeFile prvFileOut sk

-- | For 'String's @keyFile@, @fileIn@, @fileOut@, uses the key in
-- @keyFile@ to encrypt the contents of @fileIn@, writing the ciphertext
-- to @fileOut@.
encryptIO :: String -> String -> String -> IO ()
encryptIO keyFile fileIn fileOut = do
  k <- BS.readFile keyFile
  m <- BS.readFile fileIn
  g <- newStdGen
  let encrypted = encrypt g k m
  BS.writeFile fileOut encrypted

-- | For 'String's @keyFile@, @fileIn@, @fileOut@, uses the key in
-- @keyFile@ to decrypt the contents of @fileIn@, writing the message
-- to @fileOut@.
decryptIO :: String -> String -> String -> IO ()
decryptIO keyFile fileIn fileOut = do
  k <- BS.readFile keyFile
  c <- BS.readFile fileIn
  let decrypted = decrypt k c
  BS.writeFile fileOut decrypted

-- | For 'RandomGen' g and 'Integral' @n@ in @(1024, 2048, 4096)@, returns
-- 'Just' @(pk, sk)@. If @n@ is not a valid key-size then returns 'Nothing'.
keygen :: (RandomGen g, Integral a) => g -> a -> Maybe (ByteString, ByteString)
keygen g size = case size of
  s 
    | s `elem` [1024, 2048, 4096] -> Just (publicKey, privateKey)
    | otherwise -> Nothing
    where (p, q) = Internal.genModulus g size
          e = 65537
          d = NT.findInverse e p q
          publicKey = Internal.keyToByteString Key {keyModulus = p*q, keyExponent = e}
          privateKey = Internal.keyToByteString Key {keyModulus = p*q, keyExponent = d}

-- | For 'RandomGen' g and 'ByteString's @k@ and @m@, returns the encrypted
-- 'ByteString' ciphertext. If AES keygen fails then returns 'ByteString.empty'.
encrypt :: (RandomGen g) => g -> ByteString -> ByteString -> ByteString
encrypt g k m =
  case AES.keygen g 256 of
    Nothing -> BS.empty
    Just aesKeyBytes ->
      let aesKeyInt = C.word8ListToInt $ BS.unpack aesKeyBytes
          ciphertext = AES.encrypt aesKeyBytes m
          Key {keyModulus = modulus, keyExponent = e} = Internal.byteStringToKey k
          encryptedAesKey = C.intToByteString $ NT.powModN aesKeyInt e modulus
      in encryptedAesKey `BS.append` (fromRight BS.empty ciphertext)

-- | For 'ByteString's @k@ and @c@, returns the decrypted 'ByteString' message.
decrypt :: ByteString -> ByteString -> ByteString
decrypt k c = decryptedText
  where Key {keyModulus = modulus, keyExponent = d} = Internal.byteStringToKey k
        (encryptedAesKey, ciphertext) = C.byteStringToInt c
        decryptedAesKey = NT.powModN encryptedAesKey d modulus
        aesKeyBytes = BS.pack $ C.intToWord8List decryptedAesKey []
        decryptedText = (fromRight BS.empty) $ AES.decrypt aesKeyBytes ciphertext

