module Main where

import qualified System.Environment as Env
import qualified RSA
import qualified AES

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
    _     -> print "Valid keygen algorithms are: aes"

encrypt :: [String] -> IO ()
encrypt (x:xs) = do
  let algorithm = x
  case algorithm of
    "aes" -> encryptAES xs
    _     -> print "Valid encrypt algorithms are: aes"

decrypt :: [String] -> IO ()
decrypt (x:xs) = do
  let algorithm = x
  case algorithm of
    "aes" -> decryptAES xs
    _     -> print "Valid decrypt algorithms are: aes"

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
  let (key, fileIn, fileOut) = setupAES args
  AES.encryptIO key fileIn fileOut

decryptAES :: [String] -> IO ()
decryptAES args = do
  let (key, fileIn, fileOut) = setupAES args
  AES.decryptIO key fileIn fileOut

setupAES :: [String] -> (String, String, String)
setupAES (x:xs) = (key, fileIn, fileOut)
  where key = x
        fileIn = head xs
        fileOut = xs !! 1