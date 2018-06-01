module RSA
( keygen
, encrypt
, decrypt
, modulus
, publicExp
, privateExp
, rsaKeyToByteString
, byteStringToRsaKey
) where

import qualified Data.Bits as B (shiftL, shiftR)
import Data.List
import Data.Maybe
import Data.Word (Word8)

import System.Random (RandomGen)
import System.Random as Random (next, newStdGen)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (append, cons, head, empty, pack, readFile, unpack, writeFile)

import qualified AES
import qualified NumberTheory as NT
import qualified Common as C

data Key = Key {
  modulus :: !Integer
, publicExp :: !Integer
, privateExp :: !Integer
}

-- TODO:
-- key tests
-- clean up key stuff
-- fix keys (dLen can be over 1 byte if key is > 1024 bits)

keygen :: (RandomGen g, Integral a) => g -> a -> Maybe Key
keygen g size = case size of
  s 
    | s `elem` [1024, 2048, 4096] -> Just key
    | otherwise -> Nothing
    where (p, q) = genModulus g size
          e = 65537
          d = NT.findInverse e p q
          key = Key {modulus = p*q, publicExp = e, privateExp = d}

-- TODO: these will take a key file name and message file name
encrypt :: (RandomGen g) => g -> ByteString -> ByteString -> ByteString
encrypt g k m = BS.empty --encrypted
  where aesKey = fromJust $ AES.keygen g 256
        ciphertext = AES.encrypt aesKey m
        rsaKey = BS.unpack k
        encryptedKey = 0

rsaKeyToByteString :: Key -> (ByteString, ByteString)
rsaKeyToByteString key = (publicKey, privateKey)
  where m = C.intToWord8List (modulus key) []
        e = C.intToWord8List (publicExp key) []
        d = C.intToWord8List (privateExp key) []
        mLen = fromIntegral $ length m
        eLen = fromIntegral $ length e
        dLen = fromIntegral $ length d
        mBytes = BS.pack m
        eBytes = BS.pack e
        dBytes = BS.pack d
        publicKey = BS.cons eLen eBytes `BS.append` BS.cons mLen mBytes
        privateKey = BS.cons dLen dBytes `BS.append` BS.cons mLen mBytes

byteStringToRsaKey :: (ByteString, ByteString) -> Key
byteStringToRsaKey (publicKey, privateKey) = key
  where (eLen:pubBytes) = BS.unpack publicKey
        eLen' = fromIntegral eLen
        e = C.word8ListToInt $ take eLen' pubBytes
        modulus = C.word8ListToInt $ drop (eLen'+1) pubBytes
        (dLen:prvBytes) = BS.unpack privateKey
        dLen' = fromIntegral dLen
        d = C.word8ListToInt $ take dLen' prvBytes
        key = Key {modulus = modulus, publicExp = e, privateExp = d}
  

decrypt = NT.powModN

genModulus :: (RandomGen a, Integral b) => a -> b -> (Integer, Integer)
genModulus g size = (p, q)
  where p = NT.genPrime g $ size `div` 2
        q = NT.genPrime g' $ size `div` 2
        g' = snd $ Random.next g