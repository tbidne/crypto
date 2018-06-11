module AES.API
( keygenIO
, encryptIO
, decryptIO
, keygen
, encrypt
, decrypt
)
where

import System.Random (RandomGen)
import qualified System.Random as R (newStdGen, randomR)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (cons, drop, empty, pack, readFile, reverse, unpack, writeFile)

import qualified AES.Internal as Internal
import qualified Common

-- Based on FIPS 197: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
-- TODO:
-- modes (CBC, counter)
-- folds
-- testing
-- refactor
-- common utility file 

------------------
-- IO Functions --
------------------

keygenIO :: Int -> String -> IO ()
keygenIO size filename = do
  g <- R.newStdGen
  let key = keygen g size
  case key of
    Nothing -> putStrLn "wrong key size"
    Just k -> BS.writeFile filename k

encryptIO :: String -> String -> String -> IO ()
encryptIO keyFile fileIn fileOut = do
  k <- BS.readFile keyFile
  m <- BS.readFile fileIn
  let encrypted = encrypt k m
  BS.writeFile fileOut encrypted

decryptIO :: String -> String -> String -> IO ()
decryptIO keyFile fileIn fileOut = do
  k <- BS.readFile keyFile
  c <- BS.readFile fileIn
  let decrypted = decrypt k c
  BS.writeFile fileOut decrypted

-------------------
-- API Functions --
-------------------

-- Generates number in [2^(n-1)], 2^n - 1], turns into ByteString
keygen :: (RandomGen a) => a -> Int -> Maybe ByteString
keygen g size = case size of
  s 
    | s `elem` [128, 192, 256] -> Just key
    | otherwise -> Nothing
    where num = fst $ R.randomR(2^(size-1), 2^size - 1) g :: Integer
          bytes = Common.intToWord8List num []
          key = BS.pack bytes

-- Encrypts message m with key k
encrypt :: ByteString -> ByteString -> ByteString
encrypt k m = BS.cons numPadding encrypted
  where (maxRound, roundKeys) = Internal.setupForTransform k
        (numPadding, padded) = Common.padToN 16 $ BS.unpack m
        encrypted = Internal.ecb maxRound Internal.encryptInit roundKeys padded BS.empty

-- Decrypts message c with key k
decrypt :: ByteString -> ByteString -> ByteString
decrypt k c = unpadded
  where (maxRound, roundKeys) = Internal.setupForTransform k
        byteList = BS.unpack c
        numPadding = fromIntegral $ head byteList
        decrypted = Internal.ecb maxRound Internal.decryptInit roundKeys (drop 1 byteList) BS.empty
        unpadded = BS.reverse $ BS.drop numPadding $ BS.reverse decrypted