{-|
Module      : AES.API
Description : API for AES functions.
License     : MIT
Maintainer  : tbidne@gmail.com

This is the API for the main AES functions. Supports 128, 192, and 256 bit keys.
Only supports ECB mode as of now.

Based on FIPS 197: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

-}
module AES.API
( keygenIO
, encryptIO
, decryptIO
, keygen
, encrypt
, decrypt
)
where

import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (cons, drop, empty, pack, readFile, reverse, unpack, writeFile)
import           System.Random (RandomGen, newStdGen, randomR)

import qualified AES.Internal as Internal
import qualified Common

------------------
-- IO Functions --
------------------

-- | For 'Integral' @n@ and 'String' @fileOut@, creates an
-- @n@ bit key pair and writes the key to @fileOut@.
keygenIO :: Int -> String -> IO ()
keygenIO size filename = do
  g <- newStdGen
  let key = keygen g size
  case key of
    Nothing -> putStrLn "wrong key size"
    Just k -> BS.writeFile filename k

-- | For 'String's @keyFile@, @fileIn@, @fileOut@, uses the key in
-- @keyFile@ to encrypt the contents of @fileIn@, writing the ciphertext
-- to @fileOut@.
encryptIO :: String -> String -> String -> IO ()
encryptIO keyFile fileIn fileOut = do
  k <- BS.readFile keyFile
  m <- BS.readFile fileIn
  let encrypted = encrypt k m
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

-------------------
-- API Functions --
-------------------

-- | For 'RandomGen' g and 'Integral' @n@ in @(128, 192, 256)@, returns
-- 'Just' @key@. If @n@ is not a valid key-size then returns 'Nothing'.
keygen :: (RandomGen a) => a -> Int -> Maybe ByteString
keygen g size = case size of
  s 
    | s `elem` [128, 192, 256] -> Just key
    | otherwise -> Nothing
    where num = fst $ randomR(2^(size-1), 2^size - 1) g :: Integer
          bytes = Common.intToWord8List num []
          key = BS.pack bytes

-- | For 'ByteString's @k@ and @m@, returns the encrypted 'ByteString'
-- ciphertext. If AES keygen fails then returns 'ByteString.empty'.
encrypt :: ByteString -> ByteString -> ByteString
encrypt k m = BS.cons numPadding encrypted
  where (maxRound, roundKeys) = Internal.setupForTransform k
        (numPadding, padded) = Common.padToN 16 $ BS.unpack m
        encrypted = Internal.ecb maxRound Internal.encryptInit roundKeys padded BS.empty

-- | For 'ByteString's @k@ and @c@, returns the decrypted 'ByteString' message.
decrypt :: ByteString -> ByteString -> ByteString
decrypt k c = unpadded
  where (maxRound, roundKeys) = Internal.setupForTransform k
        byteList = BS.unpack c
        numPadding = fromIntegral $ head byteList
        decrypted = Internal.ecb maxRound Internal.decryptInit roundKeys (drop 1 byteList) BS.empty
        unpadded = BS.reverse $ BS.drop numPadding $ BS.reverse decrypted