module RSA.API
( keygenIO
, encryptIO
, decryptIO
, keygen
, encrypt
, decrypt
) where

import Data.Maybe (fromJust)
import Data.Word (Word8)

import System.Random (RandomGen)
import qualified System.Random as R (newStdGen)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (append, pack, readFile, unpack, writeFile)

import qualified AES.API as AES
import qualified Common as C
import qualified NumberTheory as NT
import RSA.Internal (Key (..))
import qualified RSA.Internal as Internal

keygenIO :: Integral a => a -> String -> String -> IO ()
keygenIO size pubFileOut prvFileOut = do
  g <- R.newStdGen
  let key = keygen g size
  case key of
    Nothing -> putStrLn "wrong file size"
    Just (public, private) -> do
      BS.writeFile pubFileOut public
      BS.writeFile prvFileOut private

encryptIO :: String -> String -> String -> IO ()
encryptIO keyFile fileIn fileOut = do
  k <- BS.readFile keyFile
  m <- BS.readFile fileIn
  g <- R.newStdGen
  let encrypted = encrypt g k m
  BS.writeFile fileOut encrypted

decryptIO :: String -> String -> String -> IO ()
decryptIO keyFile fileIn fileOut = do
  k <- BS.readFile keyFile
  c <- BS.readFile fileIn
  let decrypted = decrypt k c
  BS.writeFile fileOut decrypted

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

encrypt :: (RandomGen g) => g -> ByteString -> ByteString -> ByteString
encrypt g k m = encryptedAesKey `BS.append` ciphertext
  where aesKeyBytes = fromJust $ AES.keygen g 256
        aesKeyInt = C.word8ListToInt $ BS.unpack aesKeyBytes
        ciphertext = AES.encrypt aesKeyBytes m
        Key {keyModulus = modulus, keyExponent = e} = Internal.byteStringToKey k
        encryptedAesKey = C.intToByteString $ NT.powModN aesKeyInt e modulus

decrypt :: ByteString -> ByteString -> ByteString
decrypt k m = decryptedText
  where Key {keyModulus = modulus, keyExponent = d} = Internal.byteStringToKey k
        (encryptedAesKey, ciphertext) = C.byteStringToInt m
        decryptedAesKey = NT.powModN encryptedAesKey d modulus
        aesKeyBytes = BS.pack $ C.intToWord8List decryptedAesKey []
        decryptedText = AES.decrypt aesKeyBytes ciphertext

