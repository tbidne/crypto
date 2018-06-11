module Main where

import qualified System.Environment as Env
import qualified RSA.API as RSA
import qualified AES.API as AES

-------------------
-- Parse Command --
-------------------

main :: IO ()
main = do
  args <- Env.getArgs
  let command = head args
  case command of
    "keygen"  -> keygen $ drop 1 args
    "encrypt" -> encrypt $ drop 1 args
    "decrypt" -> decrypt $ drop 1 args
    _         -> print "Valid commands are: keygen, encrypt, decrypt"

-------------------
-- Parse options --
-------------------

keygen :: [String] -> IO ()
keygen (x:xs) = do
  let algorithm = x
  case algorithm of
    "aes" -> keygenAES xs
    "rsa" -> keygenRSA xs
    _     -> print "Valid keygen algorithms are: aes, rsa"

encrypt :: [String] -> IO ()
encrypt (x:xs) = do
  let algorithm = x
  case algorithm of
    "aes" -> encryptAES xs
    "rsa" -> encryptRSA xs
    _     -> print "Valid encrypt algorithms are: aes, rsa"

decrypt :: [String] -> IO ()
decrypt (x:xs) = do
  let algorithm = x
  case algorithm of
    "aes" -> decryptAES xs
    "rsa" -> decryptRSA xs
    _     -> print "Valid decrypt algorithms are: aes, rsa"

---------
-- RSA --
---------

keygenRSA :: [String] -> IO ()
keygenRSA args = do
  let size = read $ head args
  let pubFileOut = args !! 1
  let prvFileOut = args !! 2
  RSA.keygenIO size pubFileOut prvFileOut

encryptRSA :: [String] -> IO ()
encryptRSA args = do
  let (key, fileIn, fileOut) = setup args
  RSA.encryptIO key fileIn fileOut

decryptRSA :: [String] -> IO ()
decryptRSA args = do
  let (key, fileIn, fileOut) = setup args
  RSA.decryptIO key fileIn fileOut

---------
-- AES --
---------

keygenAES :: [String] -> IO ()
keygenAES args = do
  let size = read $ head args
  let fileOut = args !! 1
  AES.keygenIO size fileOut

encryptAES :: [String] -> IO ()
encryptAES args = do
  let (key, fileIn, fileOut) = setup args
  AES.encryptIO key fileIn fileOut

decryptAES :: [String] -> IO ()
decryptAES args = do
  let (key, fileIn, fileOut) = setup args
  AES.decryptIO key fileIn fileOut

------------
-- Helper --
------------

setup :: [String] -> (String, String, String)
setup (x:xs) = (key, fileIn, fileOut)
  where key = x
        fileIn = head xs
        fileOut = xs !! 1