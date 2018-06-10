module AESIntSpec
( spec
)
where

import Data.ByteString.Lazy (ByteString, unpack, writeFile)
import Data.Maybe (fromJust, isNothing)
import System.Process (callCommand)
import System.Random (newStdGen)
import Test.Hspec

import qualified AES

spec :: Spec
spec = do
  describe "IO end to end" $ do
    it "should encrypt and decrypt file with 128 bit key" $ do
      encryptAndDecrypt 128

    it "should encrypt and decrypt file with 192 bit key" $ do
      encryptAndDecrypt 192
      
    it "should encrypt and decrypt file with 256 bit key" $ do
      encryptAndDecrypt 256

encryptAndDecrypt :: Int -> Expectation
encryptAndDecrypt keySize = do
  let keyFile = "key"
  let plaintext = "plaintext"
  let ciphertext = "ciphertext"
  let decrypted = "decrypted"
  let contents = "some longer unaligned message idk"

  callCommand $ "echo " ++ contents ++ " > " ++ plaintext

  AES.keygenIO keySize keyFile
  AES.encryptIO keyFile plaintext ciphertext
  AES.decryptIO keyFile ciphertext decrypted

  result <- readFile decrypted
  callCommand $ "rm " ++ keyFile ++ " " ++ plaintext ++ " " ++
                ciphertext ++ " " ++ " " ++ decrypted
  result `shouldBe` contents ++ "\n"