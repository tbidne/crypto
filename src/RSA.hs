module RSA
( keygenIO
, encryptIO
, decryptIO
, keygen
, encrypt
, decrypt
) where

import qualified Data.Bits as B (shiftL, shiftR)
import Data.List
import Data.Maybe
import Data.Word (Word8)

import System.Random (RandomGen)
import System.Random as Random (next, newStdGen)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (append, cons, head, length, empty, pack, readFile, unpack, writeFile)

import qualified AES
import qualified NumberTheory as NT
import qualified Common as C

data Key = Key {
  keyModulus :: !Integer
, keyExponent :: !Integer
}

keygenIO :: Int -> String -> String -> IO ()
keygenIO size pubFileOut prvFileOut = do
  g <- Random.newStdGen
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
  g <- Random.newStdGen
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
    where (p, q) = genModulus g size
          e = 65537
          d = NT.findInverse e p q
          publicKey = keyToByteString Key {keyModulus = p*q, keyExponent = e}
          privateKey = keyToByteString Key {keyModulus = p*q, keyExponent = d}

encrypt :: (RandomGen g) => g -> ByteString -> ByteString -> ByteString
encrypt g k m = encryptedAesKey `BS.append` ciphertext
  where aesKeyBytes = fromJust $ AES.keygen g 256
        aesKeyInt = C.word8ListToInt $ BS.unpack aesKeyBytes
        ciphertext = AES.encrypt aesKeyBytes m
        Key {keyModulus = modulus, keyExponent = e} = byteStringToKey k
        encryptedAesKey = C.intToByteString $ NT.powModN aesKeyInt e modulus

decrypt :: ByteString -> ByteString -> ByteString
decrypt k m = decryptedText
  where Key {keyModulus = modulus, keyExponent = d} = byteStringToKey k
        (encryptedAesKey, ciphertext) = C.byteStringToInt m
        decryptedAesKey = NT.powModN encryptedAesKey d modulus
        aesKeyBytes = BS.pack $ C.intToWord8List decryptedAesKey []
        decryptedText = AES.decrypt aesKeyBytes ciphertext

keyToByteString :: Key -> ByteString
keyToByteString key = eBytes `BS.append` mBytes
  where  eBytes = C.intToByteString (keyExponent key)
         mBytes = C.intToByteString (keyModulus key)

byteStringToKey :: ByteString -> Key
byteStringToKey keyBytes = key
  where (e, mBS) = C.byteStringToInt keyBytes
        (m,_) = C.byteStringToInt mBS
        key = Key {keyModulus = m, keyExponent = e}  

genModulus :: (RandomGen a, Integral b) => a -> b -> (Integer, Integer)
genModulus g size = (p, q)
  where p = NT.genPrime g $ size `div` 2
        q = NT.genPrime g' $ size `div` 2
        g' = snd $ Random.next g

